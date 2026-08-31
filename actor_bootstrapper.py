"""Automatic provisioning of isolated principals for authorization testing."""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from runtime_executor import RequestExecutor
from state_store import ActorContext, MultiActorContextStore, StateStore

log = logging.getLogger("actor_bootstrapper")


@dataclass
class BootstrapResult:
    success: bool
    actors: MultiActorContextStore = field(default_factory=MultiActorContextStore)
    owner_state: Optional[StateStore] = None
    signup_api_id: str = ""
    login_api_id: str = ""
    errors: List[str] = field(default_factory=list)


class ActorBootstrapper:
    """Discover signup/login operations and provision two same-role users."""

    SIGNUP_RE = re.compile(r"signup|sign[_-]?up|register|registration|create[_-]?(user|account)", re.I)
    LOGIN_RE = re.compile(r"login|log[_-]?in|signin|sign[_-]?in|authenticate|issue[_-]?token", re.I)
    EXCLUDED_AUTH_RE = re.compile(r"logout|refresh|forgot|reset|verify|otp|captcha", re.I)

    def __init__(self, operations: List[Dict], executor: RequestExecutor):
        self.operations = operations
        self.executor = executor

    def discover_auth_operations(self) -> Tuple[Optional[Dict], Optional[Dict]]:
        signup = self._best_match(self.SIGNUP_RE, exclude=None)
        login = self._best_match(self.LOGIN_RE, exclude=self.EXCLUDED_AUTH_RE)
        return signup, login

    def _best_match(self, pattern: re.Pattern, exclude: Optional[re.Pattern]) -> Optional[Dict]:
        candidates = []
        for operation in self.operations:
            method = operation.get("method", "GET").upper()
            if method not in ("POST", "PUT"):
                continue
            tags = " ".join(str(tag) for tag in operation.get("tags", []))
            text = " ".join((
                str(operation.get("id", "")),
                str(operation.get("path", "")),
                tags,
            ))
            if not pattern.search(text) or (exclude and exclude.search(text)):
                continue
            input_names = {
                str(meta.get("original", name) if isinstance(meta, dict) else name).lower()
                for name, meta in (operation.get("inputs", {}) or {}).items()
            }
            score = 0
            score += 4 if method == "POST" else 1
            score += 3 if any("password" in name or name == "pass" for name in input_names) else 0
            score += 2 if any("email" in name or "username" in name or "number" in name for name in input_names) else 0
            score -= len(input_names) / 100.0
            candidates.append((score, operation))
        return max(candidates, key=lambda item: item[0])[1] if candidates else None

    def bootstrap(self, base_state: Optional[Dict] = None) -> BootstrapResult:
        signup, login = self.discover_auth_operations()
        result = BootstrapResult(
            success=False,
            signup_api_id=signup.get("id", "") if signup else "",
            login_api_id=login.get("id", "") if login else "",
        )
        if signup is None:
            result.errors.append("No supported signup/register operation found in OpenAPI")
            return result
        if login is None:
            result.errors.append("No supported login/signin operation found in OpenAPI")
            return result

        states = []
        for actor_id in ("owner_a", "user_b"):
            state, error = self._bootstrap_actor(actor_id, signup, login, base_state or {})
            if error:
                result.errors.append(error)
                return result
            states.append(state)

        for state in states:
            actor = self._actor_from_state(state)
            result.actors.add(actor)
        result.actors.add(ActorContext(actor_id="anonymous", role="anonymous"))
        result.owner_state = states[0]
        result.success = True
        return result

    def _bootstrap_actor(self, actor_id: str, signup: Dict, login: Dict,
                         base_state: Dict) -> Tuple[Optional[StateStore], str]:
        state_data = dict(base_state)
        # Never leak a manually configured token into an automatically-created actor.
        state_data.pop("auth_token", None)
        state_data.pop("refresh_token", None)
        state_data.pop("auth_cookies", None)
        state_data["actor_id"] = actor_id
        state_data["actor_role"] = "user"
        state = StateStore(state_data)

        signup_result = self.executor.execute_request(signup, state, allow_repair=True)
        if signup_result.get("status") not in (200, 201, 202, 204):
            return None, (
                f"Actor {actor_id}: signup failed with HTTP {signup_result.get('status')} "
                f"via {signup.get('id')}"
            )

        if not self._has_auth_session(state):
            login_result = self.executor.execute_request(login, state, allow_repair=True)
            if login_result.get("status") not in (200, 201, 202, 204):
                hint = login_result.get("response_text", "").lower()
                suffix = " (OTP/CAPTCHA/manual verification required)" if re.search(
                    r"otp|verify|captcha|two.?factor|2fa", hint
                ) else ""
                return None, (
                    f"Actor {actor_id}: login failed with HTTP {login_result.get('status')}"
                    f" via {login.get('id')}{suffix}"
                )

        if not self._has_auth_session(state):
            return None, f"Actor {actor_id}: login succeeded but no token or auth cookie was extracted"
        return state, ""

    @staticmethod
    def _has_auth_session(state: StateStore) -> bool:
        return bool(state.get("auth_token") or state.get("auth_cookies"))

    @staticmethod
    def _actor_from_state(state: StateStore) -> ActorContext:
        credential_keys = (
            "email", "username", "name", "password", "phone", "mobile", "number", "user_id"
        )
        credentials = {key: state.get(key) for key in credential_keys if state.get(key) is not None}
        return ActorContext(
            actor_id=state.get("actor_id"),
            role=state.get("actor_role", "user"),
            auth_token=state.get("auth_token", ""),
            refresh_token=state.get("refresh_token", ""),
            credentials=credentials,
            cookies=dict(state.get("auth_cookies", {}) or {}),
        )
