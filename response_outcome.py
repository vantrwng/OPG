"""Classify transport success separately from application-level success."""

import json
import re
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class ResponseOutcome:
    successful: bool
    semantic_failure: bool = False
    reason: str = ""


_FAILURE_STATUS_VALUES = {
    "fail", "failed", "failure", "error", "errored", "invalid",
    "denied", "forbidden", "unauthorized", "unsuccessful", "rejected",
}


def evaluate_response(
    http_status: int,
    response_json: Any = None,
    response_text: str = "",
    expected_statuses: Optional[list] = None,
) -> ResponseOutcome:
    """Evaluate an HTTP response without rewriting its real status code.

    A 2xx response can still be a business failure, for example
    ``{"status": "fail", "message": "User already exists"}``.
    """
    try:
        status = int(http_status)
    except (TypeError, ValueError):
        return ResponseOutcome(False, reason=f"Invalid HTTP status: {http_status}")

    if not 200 <= status < 300:
        return ResponseOutcome(False, reason=f"HTTP {status}")

    # Collabtive's legacy api.php historically returned this authentication
    # error as HTTP 200 with a plain-text body.  Treat it as an application
    # failure before the response-contract validator can misclassify it as an
    # HTML/API media-type mismatch.  Newer target code returns HTTP 401, but
    # keeping this guard makes reports correct against older deployments too.
    if str(response_text or "").strip().casefold() == "not authorized":
        return ResponseOutcome(
            False,
            semantic_failure=True,
            reason="Authentication rejected: not authorized",
        )

    expected = {str(code).upper() for code in (expected_statuses or [])}
    if expected and str(status) not in expected and "2XX" not in expected:
        return ResponseOutcome(
            False,
            semantic_failure=True,
            reason=f"HTTP {status} is not an expected OpenAPI success status",
        )

    body = response_json
    if body is None and response_text:
        try:
            body = json.loads(response_text)
        except (TypeError, ValueError, json.JSONDecodeError):
            body = None

    if not isinstance(body, dict):
        return ResponseOutcome(True)

    status_value = body.get("status")
    if isinstance(status_value, str):
        normalized = status_value.strip().lower()
        if normalized in _FAILURE_STATUS_VALUES or normalized.startswith("fail"):
            return ResponseOutcome(
                False,
                semantic_failure=True,
                reason=f"Response field status={status_value!r}",
            )

    for key in ("success", "ok"):
        if body.get(key) is False:
            return ResponseOutcome(
                False,
                semantic_failure=True,
                reason=f"Response field {key}=false",
            )

    for key in ("error", "errors"):
        value = body.get(key)
        if value not in (None, "", False, [], {}):
            return ResponseOutcome(
                False,
                semantic_failure=True,
                reason=f"Response contains non-empty {key} field",
            )

    return ResponseOutcome(True)


def result_succeeded(result: dict) -> bool:
    """Read executor output, with compatibility for older/mocked results."""
    if "successful" in result:
        return bool(result["successful"])
    return evaluate_response(
        result.get("status", 0),
        response_json=result.get("raw_response"),
        response_text=result.get("response_text", ""),
    ).successful


_MISSING_AUTH_IDENTITY_PATTERNS = (
    re.compile(r"none.?type.{0,80}(username|email|user_id|userid)", re.I | re.S),
    re.compile(r"(authenticated |token )?(user|identity|principal).{0,40}not found", re.I | re.S),
    re.compile(r"no (user|identity|principal).{0,40}(token|subject|sub)", re.I | re.S),
    re.compile(r"missing (user|identity|principal) in session", re.I | re.S),
)


def is_auth_state_mismatch(result: dict, state) -> bool:
    """Detect a decoded token whose subject no longer resolves in the target DB."""
    if not state.get("auth_token") and not state.get("auth_cookies"):
        return False
    status = int(result.get("status", 0) or 0)
    if status not in (200, 400, 401, 404, 500):
        return False
    evidence = " ".join((
        str(result.get("response_text", "")),
        str(result.get("raw_response", "")),
        " ".join(str(item) for item in result.get("anomaly_details", [])),
    ))
    has_missing_identity_evidence = any(
        pattern.search(evidence) for pattern in _MISSING_AUTH_IDENTITY_PATTERNS
    )
    if not has_missing_identity_evidence:
        return False

    # A 500 from /me-style code can lack an explicit identity parameter; the
    # NoneType traceback is already strong evidence. For a normal 404/400/200
    # "user not found", recover auth only when the request targeted the same
    # username/user_id/email that belongs to the token principal. This avoids
    # recreating the actor merely because an unrelated resource is absent.
    if status == 500 and re.search(
        r"none.?type.{0,80}(username|email|user_id|userid)", evidence, re.I | re.S
    ):
        return True
    if status == 401 and re.search(
        r"missing (user|identity|principal) in session", evidence, re.I | re.S
    ):
        return True

    payload = result.get("sent_payload", {})
    if not isinstance(payload, dict):
        return False
    for field_name, value in payload.items():
        principal = state.get_actor_identity(str(field_name))
        if principal is not None and str(value).casefold() == str(principal).casefold():
            return True
    return False
