import json
import re
import uuid
import logging
import requests
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from state_store import AuthTransport, StateStore
from llm_planner import LLMPlanner
from response_outcome import evaluate_response, is_auth_state_mismatch, result_succeeded
from file_artifacts import FileArtifactProvider
from knowledge_memory import sanitize_sensitive

log = logging.getLogger("executor")
REQUEST_TIMEOUT = 10
MAX_SAME_ORIGIN_REDIRECTS = 5


@dataclass
class PreparedRequest:
    """Canonical HTTP request used by both baseline and attack execution.

    Keeping the transport representation explicit prevents an attack payload from
    being regenerated or silently moved to the wrong HTTP location.
    """

    api_id: str
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, Any] = field(default_factory=dict)
    cookies: Dict[str, Any] = field(default_factory=dict)
    json_body: Optional[Dict[str, Any]] = None
    form_body: Optional[Dict[str, Any]] = None
    files: Optional[Dict[str, Any]] = None
    file_metadata: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    raw_body: Optional[bytes] = None
    payload_source: str = "NONE"

    @property
    def sent_payload(self) -> Dict[str, Any]:
        if self.json_body is not None:
            return self.json_body
        if self.form_body is not None:
            return self.form_body
        return self.query_params

# Regex phát hiện mọi biến thể của lỗi "trùng lặp" từ các framework khác nhau
# Django REST / FastAPI / Express / Spring / Rails / Laravel ...
DUPLICATE_RE = re.compile(
    r"already (exists?|registered|taken|used|in use)"
    r"|duplicate (entry|key|value|field|email|username)"
    r"|(email|username|phone|slug|title|name).*?(already|already exists|is taken|is used|conflict)"
    r"|conflict(ing)? (resource|entry|record|key)?"
    r"|unique.*?(constraint|violation)"
    r"|this (email|username|phone|account) (is already|already|has been)"
    r"|has already been taken"
    r"|UNIQUE constraint failed"
    r"|Duplicate entry",
    re.I
)

class FeedbackAnalyzer:
    _EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    _PHONE_RE = re.compile(r"\+?\d[\d\s\-]{7,14}\d")
    _ID_RE = re.compile(r"[\"'](id|[a-zA-Z_]*id)[\"']\s*:\s*([0-9]+|[\"'][a-zA-Z0-9\-_]+[\"'])", re.I)

    def analyze(self, response: requests.Response, state: StateStore,
                sent_payload: Dict) -> Dict[str, Any]:
        """
        Generic Response Analyzer: Trích xuất các evidence từ response để cung cấp cho LLM (AuditorAgent)
        Không tự đưa ra kết luận về BOLA/IDOR ở đây.
        """
        status     = response.status_code
        body_text  = response.text
        
        result = {
            "status": status,
            "has_token": state.has_authentication(),
            "extracted_emails": [],
            "extracted_phones": [],
            "extracted_ids": [],
            "anomaly_details": [],
            "server_error": False,
        }

        if status >= 500:
            result["server_error"] = True
            result["anomaly_details"].append(f"HTTP {status} — possible crash/unhandled exception")
            log.error(f"\033[91m[!!!] SERVER ERROR {status}\033[0m — possible vulnerability!")

        # Trích xuất toàn bộ emails và phones
        emails_found = list(set(self._EMAIL_RE.findall(body_text)))
        phones_found = list(set(self._PHONE_RE.findall(body_text)))
        if emails_found: result["extracted_emails"] = emails_found[:5]
        if phones_found: result["extracted_phones"] = phones_found[:5]
        
        # Trích xuất tất cả các trường có vẻ là ID (id, user_id, order_id...)
        ids_found = self._ID_RE.findall(body_text)
        if ids_found:
            # ids_found là list of tuples: [('id', '123'), ('userId', '456')]
            unique_ids = list(set([f"{k}={v}" for k, v in ids_found]))
            result["extracted_ids"] = unique_ids[:10]

        log.info(f"\033[95m[EXTRACTED EVIDENCE]\033[0m Emails: {len(result['extracted_emails'])}, Phones: {len(result['extracted_phones'])}, IDs: {len(result['extracted_ids'])}")

        return result


class RequestExecutor:
    _LOGIN_OPERATION_RE = re.compile(
        r"login|log[_-]?in|signin|sign[_-]?in|authenticate|issue[_-]?token",
        re.I,
    )
    _LOGIN_REJECTION_RE = re.compile(
        r"username.{0,30}password.{0,30}(incorrect|invalid|wrong)"
        r"|invalid credentials|bad credentials|authentication failed|login failed",
        re.I | re.S,
    )

    def __init__(self, base_url: str, planner: LLMPlanner, knowledge_memory=None,
                 artifact_provider=None):
        self.base_url        = base_url.rstrip("/")
        self.planner         = planner
        self.analyzer        = FeedbackAnalyzer()
        self.memory          = knowledge_memory # Có thể dùng để ghi log requests
        self.artifact_provider = artifact_provider or FileArtifactProvider()
        self._session        = requests.Session()
        self._session.headers.update({"Accept": "application/json, */*"})
        self.auth_recovery_handler = None
        
        # State tracking cho Repair để tránh gọi LLM vô tận
        self._repair_budget = {}  # key: f"{api_id}:{status}", value: int
        self._repair_seen = set() # key: f"{api_id}:{status}:{hash(payload)}"

    def execute_request(self, api_node: Dict, current_state: StateStore,
                        edge_deps: Optional[list] = None,
                        payload_override: Optional[Dict[str, Any]] = None,
                        payload_source_override: Optional[str] = None,
                        payload_patch: Optional[Dict[str, Any]] = None,
                        allow_repair: bool = True,
                        allow_auth_recovery: bool = True) -> Dict[str, Any]:
        api_id  = api_node.get("id", "unknown_api")
        method  = api_node.get("method", "GET").upper()

        if payload_override is None:
            sent_payload, payload_source = self.planner.generate_payload(
                api_node, current_state, edge_deps=edge_deps
            )
        else:
            sent_payload = dict(payload_override)
            payload_source = payload_source_override or "EXPLICIT_OVERRIDE"
        if payload_patch:
            # Bootstrap and other orchestration layers may constrain individual
            # OpenAPI fields without replacing the planner-generated payload.
            sent_payload.update(payload_patch)
            payload_source = f"{payload_source}+CONSTRAINT"
        
        # 1. Thực thi lần đầu
        exec_result = self._do_execute(api_node, current_state, sent_payload, payload_source)

        # A login rejection cannot be healed by asking an LLM to invent another
        # password. Refresh/recreate the named actor, regenerate the payload from
        # its new frozen credential snapshot, and only then retry the login.
        if (allow_auth_recovery and payload_override is None
                and self._is_login_credential_rejection(api_node, exec_result)
                and callable(self.auth_recovery_handler)):
            current_state.mark_auth_identity(False, "login credentials rejected by target")
            recovery_event = {
                "status": exec_result.get("status"),
                "reason": exec_result.get("outcome_reason", "login credentials rejected"),
                "response": exec_result.get("response_text", "")[:1000],
            }
            recovered, recovery_reason = self._invoke_auth_recovery(
                current_state, api_node, exec_result
            )
            if recovered:
                retry_payload, retry_source = self.planner.generate_payload(
                    api_node, current_state, edge_deps=edge_deps
                )
                if payload_patch:
                    retry_payload.update(payload_patch)
                    retry_source = f"{retry_source}+CONSTRAINT"
                retry_result = self._do_execute(
                    api_node, current_state, retry_payload, retry_source
                )
                retry_result["auth_recovery"] = {
                    "attempted": True,
                    "recovered": retry_result.get("successful", False),
                    "events": [recovery_event],
                    "reason": recovery_reason,
                    "auth_context": current_state.get_auth_context(),
                }
                return retry_result
            exec_result["auth_recovery"] = {
                "attempted": True,
                "recovered": False,
                "events": [recovery_event],
                "reason": recovery_reason,
                "auth_context": current_state.get_auth_context(),
            }
            return exec_result

        # Auth-state recovery is separate from payload self-healing. A token
        # whose subject no longer exists cannot be repaired by randomizing the
        # endpoint payload.
        if allow_auth_recovery and is_auth_state_mismatch(exec_result, current_state):
            current_state.mark_auth_identity(False, "token subject missing from target database")
            exec_result["auth_state_mismatch"] = True
            exec_result["outcome_reason"] = "Auth-state mismatch: token subject does not exist"
            exec_result["server_error"] = False
            exec_result["response_diff"] = False
            exec_result["anomaly_details"] = [exec_result["outcome_reason"]]
            recovery_event = {
                "status": exec_result.get("status"),
                "reason": exec_result["outcome_reason"],
                "response": exec_result.get("response_text", "")[:1000],
            }

            recovered = False
            recovery_reason = "No auth recovery handler is configured"
            if callable(self.auth_recovery_handler):
                recovered, recovery_reason = self._invoke_auth_recovery(
                    current_state, api_node, exec_result
                )

            if recovered:
                retry_result = self._do_execute(
                    api_node, current_state, sent_payload, payload_source
                )
                retry_result["auth_recovery"] = {
                    "attempted": True,
                    "recovered": retry_result.get("successful", False),
                    "events": [recovery_event],
                    "reason": recovery_reason,
                    "auth_context": current_state.get_auth_context(),
                }
                return retry_result

            exec_result["auth_recovery"] = {
                "attempted": True,
                "recovered": False,
                "events": [recovery_event],
                "reason": recovery_reason,
                "auth_context": current_state.get_auth_context(),
            }
            return exec_result
        
        # 2. Vòng lặp Self-Healing (Tự phục hồi lỗi)
        # Chỉ áp dụng nếu lỗi >= 400 và method cho phép thay đổi body payload
        if (allow_repair and not exec_result["successful"]
                and exec_result["status"] not in (401, 403)
                and method in ("POST", "PUT", "PATCH")
                and exec_result["response_text"]):
            current_payload = sent_payload
            current_exec = exec_result
            repair_history = []
            _local_seen = set()   # local per-call, không dedup cross-beam
            
            for attempt in range(3):
                curr_status = current_exec['status']
                
                # Lưu lại lịch sử trước khi sửa
                repair_history.append({
                    "attempt": attempt + 1,
                    "status": curr_status,
                    "payload": current_payload,
                    "response": current_exec["response_text"]
                })
                
                # Tính chữ ký payload (để không sửa trùng 1 payload nhiều lần trên toàn hệ thống)
                payload_str = json.dumps(current_payload, sort_keys=True)
                payload_hash = hashlib.md5(payload_str.encode('utf-8')).hexdigest()
                
                # Budget giờ tính theo (API + Status + PayloadHash)
                budget_key = f"{api_id}:{curr_status}:{payload_hash}"
                max_repairs_allowed = 1 if curr_status >= 500 else 2
                
                if self._repair_budget.get(budget_key, 0) >= max_repairs_allowed:
                    log.info(f"\033[90m[Repair Skip]\033[0m Budget exhausted for payload signature {budget_key}")
                    current_exec["repair_skipped"] = True
                    break
                
                # Invalidate schema cache khi phát hiện lỗi trùng lặp (nhiều biến thể)
                response_text = current_exec.get("response_text", "")
                if DUPLICATE_RE.search(response_text):
                    self.planner._schema_cache.pop(api_node.get("id"), None)
                    self.planner._payload_cache.clear()  # xóa cả payload cache để LLM bắt buộc sinh mới
                    log.info(f"[Cache Invalidate] Cleared ALL caches for {api_id} — duplicate/conflict detected: {response_text[:80]}")

                # Trừ đi 1 lượt sử dụng cho chữ ký này
                self._repair_budget[budget_key] = self._repair_budget.get(budget_key, 0) + 1

                log.warning(f"\033[93m[Self-Healing]\033[0m API {api_id} returned {curr_status}. Triggering LLM repair (Attempt {attempt+1}/3)...")
                repaired_payload = self.planner.repair_payload(
                    api_node, current_state, current_payload, current_exec["response_text"], edge_deps,
                    knowledge_memory=self.memory
                )
                
                if not repaired_payload:
                    break
                    
                log.info(f"\033[96m[RETRY REQUEST]\033[0m Re-executing {api_id} with repaired payload...")
                exec_result_new = self._do_execute(api_node, current_state, repaired_payload, "LLM_REPAIR")
                log.info(f"\033[96m[NEW RESPONSE]\033[0m {api_id} returned {exec_result_new['status']}")
                exec_result_new["repair_reason"] = f"Original Error HTTP {curr_status}: {current_exec['response_text']}"
                
                # Quan trọng: Giữ lại bằng chứng nếu payload cũ đã gây ra 500 Server Error
                if exec_result["server_error"]:
                    exec_result_new["server_error"] = True
                    # Tránh chèn trùng lặp chuỗi Original 500
                    if not any("[Original 500]" in d for d in exec_result_new["anomaly_details"]):
                        exec_result_new["anomaly_details"].insert(0, f"[Original 500] {exec_result['response_text'][:100]}")
                
                if exec_result_new["successful"]:
                    log.info(f"\033[92m[Repair SUCCESS]\033[0m {api_id} fixed from {exec_result['status']} to {exec_result_new['status']}")
                    exec_result_new["repair_history"] = repair_history
                    return exec_result_new
                    
                # Cập nhật dữ liệu để nếu chạy tiếp vòng lặp, LLM sẽ nhận được lỗi MỚI
                log.warning(f"\033[91m[Repair FAILED]\033[0m {api_id} still failing with {exec_result_new['status']}")
                current_payload = repaired_payload
                current_exec = exec_result_new
                
            current_exec["repair_history"] = repair_history
            return current_exec
            
        return exec_result

    @classmethod
    def _is_login_credential_rejection(cls, api_node: Dict,
                                       result: Dict[str, Any]) -> bool:
        endpoint = " ".join((
            str(api_node.get("id", "")), str(api_node.get("path", "")),
        ))
        if not cls._LOGIN_OPERATION_RE.search(endpoint) or result_succeeded(result):
            return False
        evidence = " ".join((
            str(result.get("response_text", "")),
            str(result.get("raw_response", "")),
            str(result.get("outcome_reason", "")),
        ))
        return bool(cls._LOGIN_REJECTION_RE.search(evidence))

    def _invoke_auth_recovery(self, state: StateStore, api_node: Dict,
                              failed_result: Dict[str, Any]):
        try:
            handler_result = self.auth_recovery_handler(
                state, api_node, failed_result
            )
            if isinstance(handler_result, tuple):
                recovered = bool(handler_result[0])
                reason = str(handler_result[1]) if len(handler_result) > 1 else ""
                return recovered, reason
            recovered = bool(handler_result)
            return recovered, (
                "Auth context recovered"
                if recovered else "Auth recovery handler returned false"
            )
        except Exception as exc:
            log.error(
                "[Auth Recovery] Handler failed for %s: %s",
                api_node.get("id", "unknown_api"), exc,
            )
            return False, str(exc)

    def _do_execute(self, api_node: Dict, current_state: StateStore, sent_payload: Dict, payload_source: str) -> Dict[str, Any]:
        api_id  = api_node.get("id", "unknown_api")
        method  = api_node.get("method", "GET").upper()
        path    = api_node.get("path", "/")

        sent_payload = self._bind_principal_identity(
            api_node,
            current_state,
            sent_payload,
            payload_source,
        )

        prepared = self.prepare_request(
            api_node=api_node,
            current_state=current_state,
            payload=sent_payload,
            payload_source=payload_source,
        )
        url = prepared.url
        headers = prepared.headers

        safe_payload = sanitize_sensitive(sent_payload)
        log.info(f"\033[96m[>>]\033[0m {method} {url}  payload={json.dumps(safe_payload, ensure_ascii=False)[:120]}")

        request_started = time.perf_counter()
        response = self._fire_prepared_request(prepared)
        elapsed_ms = round((time.perf_counter() - request_started) * 1000, 2)

        if response is None:
            log.error(f"\033[91m[!!] Request failed (timeout/connection)\033[0m for {api_id}")
            failure = self._failure_result(api_id, edge_failure=False)
            failure["elapsed_ms"] = elapsed_ms
            return failure

        status = response.status_code
        safe_response_text = sanitize_sensitive(response.text)
        if status == 400:
            log.warning(f"\033[93m[400 Debug]\033[0m Server message: {safe_response_text}")
        log.info(f"{self._status_color(status)}[<<]\033[0m {status} {api_id} ({len(response.text)} bytes)")
        log.debug(f"\033[90m[RAW RESPONSE]\033[0m {str(safe_response_text)[:500]}")

        try:
            response_json = response.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            response_json = None

        outcome = evaluate_response(
            status,
            response_json,
            response.text,
            expected_statuses=api_node.get("expected_success_statuses"),
        )
        response_headers = dict(getattr(response, "headers", {}) or {})
        response_content_type = str(response_headers.get("Content-Type", ""))
        schema_valid, schema_errors = self._validate_response_contract(
            response_json, response.text if hasattr(response, "text") else "",
            response_content_type, api_node.get("outputs", {}), status,
            api_node.get("response_content_types", []),
            api_node.get("response_body_statuses"),
        )
        if outcome.successful and not schema_valid:
            outcome = type(outcome)(
                successful=False,
                semantic_failure=True,
                reason="; ".join(schema_errors) or "OpenAPI response contract mismatch",
            )
        if outcome.semantic_failure:
            log.warning(
                f"\033[93m[APPLICATION FAIL]\033[0m HTTP {status} {api_id}: "
                f"{outcome.reason}"
            )

        anomaly = self.analyzer.analyze(response, current_state, sent_payload)

        response_cookies = getattr(response, "cookies", None)
        if response_cookies is not None and hasattr(response_cookies, "get_dict"):
            cookie_dict = response_cookies.get_dict()
            if isinstance(cookie_dict, dict) and cookie_dict:
                current_state.update("auth_cookies", cookie_dict)
                for cookie_name, cookie_value in cookie_dict.items():
                    current_state.set_auth_transport(AuthTransport(
                        kind="cookie",
                        name=str(cookie_name),
                        value=cookie_value,
                        source="SET_COOKIE",
                        verified=True,
                    ))

        state_transition = False
        deleted_references = []
        if response_json and outcome.successful:
            state_transition = current_state.extract_from_response(
                response_json,
                schema=api_node.get("outputs", {}),
                api_id=api_id
            )
            token = current_state.get("auth_token")
            if token:
                current_state.set_auth_transport(AuthTransport(
                    kind="header",
                    name=current_state.get("auth_header_name", "Authorization"),
                    value=token,
                    prefix=current_state.get("auth_header_prefix", "") or "Token",
                    source="RESPONSE_TOKEN",
                    verified=False,
                ))

        # A successful write establishes request values as valid downstream
        # context, including HTTP 204 with no response body.
        if outcome.successful:
            if method in ("POST", "PUT", "PATCH"):
                request_transition = current_state.capture_successful_request(
                    sent_payload,
                    api_node.get("inputs", {}),
                )
                state_transition = state_transition or request_transition
            elif method == "DELETE":
                deleted_references = self._invalidate_successful_delete(
                    api_node, current_state, sent_payload
                )
                state_transition = bool(deleted_references) or state_transition

        edge_failure = not outcome.successful

        if edge_failure:
            log.warning(f"\033[93m[EDGE FAIL]\033[0m 400 on {api_id} — penalizing ODG edge (bad schema/FK)")

        return {
            "elapsed_ms":     elapsed_ms,
            "status":          status,
            "successful":      outcome.successful,
            "semantic_failure": outcome.semantic_failure,
            "outcome_reason":  outcome.reason,
            "server_error":    anomaly.get("server_error", False),
            "auth_anomaly":    False,  # Bỏ heuristic cứng, dời sang LLM Auditor
            "pii_leakage":     len(anomaly.get("extracted_emails", [])) > 0 or len(anomaly.get("extracted_phones", [])) > 0,
            "state_transition": state_transition,
            "deleted_references": deleted_references,
            "response_diff":   anomaly.get("server_error", False),
            "edge_failure":    edge_failure,
            "anomaly_details": anomaly.get("anomaly_details", []),
            "raw_response":    response_json,
            "response_text":   response.text if hasattr(response, 'text') else "",
            "response_headers": response_headers,
            "response_content_type": response_content_type,
            "schema_valid": schema_valid,
            "schema_errors": schema_errors,
            "sent_payload":    sent_payload,
            "sent_headers":    headers,
            "sent_query":      prepared.query_params,
            "sent_cookies":    prepared.cookies,
            "sent_files":      prepared.file_metadata,
            "actor_id":        current_state.get("actor_id", "default"),
            "auth_context":     current_state.get_auth_context(),
            "payload_source":  payload_source,
            "url":             url,
        }

    @staticmethod
    def _invalidate_successful_delete(api_node: Dict, state: StateStore,
                                      sent_payload: Dict[str, Any]) -> list:
        """Invalidate only the terminal selector of a successful DELETE path."""
        path_selectors = re.findall(r"\{([^}]+)\}", str(api_node.get("path", "")))
        if not path_selectors:
            return []
        selector = path_selectors[-1]
        value = sent_payload.get(selector)
        if value is None:
            for field_name, meta in (api_node.get("inputs", {}) or {}).items():
                meta = meta if isinstance(meta, dict) else {}
                original = meta.get("original", field_name)
                if selector not in (field_name, original):
                    continue
                value = sent_payload.get(original, sent_payload.get(field_name))
                break
        if value in (None, ""):
            return []
        state.invalidate_deleted_reference(selector, value)
        return [{
            "resource_type": api_node.get("resource_type") or api_node.get("path", ""),
            "selector_field": selector,
            "resource_id": str(value),
        }]

    @staticmethod
    def _validate_response_contract(response_json, response_text, content_type, outputs, status,
                                    expected_content_types=None, response_body_statuses=None):
        """Conservative response gate for authorization oracles.

        The parser exposes a flattened output-field map rather than a raw JSON
        Schema, so this validates media type plus declared fields/types when
        they are present without inventing required fields.
        """
        if not 200 <= int(status or 0) < 300:
            return True, []
        errors = []
        status_text = str(int(status))
        if response_body_statuses is None:
            body_declared = bool(expected_content_types or outputs)
        else:
            declared_body_statuses = {
                str(item).upper() for item in response_body_statuses
            }
            body_declared = (
                status_text in declared_body_statuses or '2XX' in declared_body_statuses
            )
        if status in (204, 205) or not body_declared:
            return True, errors
        media = str(content_type or "").split(";", 1)[0].strip().casefold()
        expected_media = {str(item).casefold() for item in (expected_content_types or [])}
        text = str(response_text or "").lstrip().casefold()
        if media == "text/html" or text.startswith("<!doctype html") or text.startswith("<html"):
            errors.append("2xx response is HTML, not an API representation")
            return False, errors

        # Collabtive can return either XML or JSON based on the ``mode`` query
        # parameter.  When both are declared by OpenAPI, an explicit XML
        # Content-Type is already sufficient; do not force the XML body
        # through the JSON parser merely because JSON is also supported.
        if media and media in expected_media and not media.endswith("+json") and media != "application/json":
            return True, errors

        expects_json = any(
            item == "application/json" or item.endswith("+json")
            for item in expected_media
        )
        if expected_media and not expects_json:
            if media and "*/*" not in expected_media and media not in expected_media:
                errors.append(f"Response Content-Type {media!r} is not declared by OpenAPI")
                return False, errors
            return True, errors
        response_outputs = {
            field: meta for field, meta in (outputs or {}).items()
            if not (isinstance(meta, dict) and (
                meta.get('_passthrough') or meta.get('_request_passthrough')
            ))
        }
        if expects_json and response_json is None:
            errors.append("OpenAPI declares a response body but JSON parsing failed")
            return False, errors
        if not isinstance(response_json, dict):
            return True, errors
        flat = StateStore._flatten(response_json)
        python_types = {
            "string": str, "integer": int, "number": (int, float),
            "boolean": bool, "object": dict, "array": list,
        }
        for field, meta in response_outputs.items():
            meta = meta if isinstance(meta, dict) else {}
            original = meta.get("original", field)
            if original not in flat:
                continue
            expected = python_types.get(str(meta.get("type", "")).casefold())
            if expected and not isinstance(flat[original], expected):
                errors.append(f"Response field {original} violates declared type {meta.get('type')}")
        return not errors, errors

    @staticmethod
    def _bind_principal_identity(api_node: Dict, state: StateStore,
                                 payload: Dict[str, Any], payload_source: str) -> Dict[str, Any]:
        """Keep valid/repair requests aligned with the authenticated principal."""
        if str(payload_source).upper().startswith("ATTACKER_") or not state.has_authentication():
            return dict(payload)

        bound_payload = dict(payload)
        for field_name, meta in (api_node.get("inputs", {}) or {}).items():
            meta = meta if isinstance(meta, dict) else {}
            if str(meta.get("in", "body")).lower() != "path":
                continue
            original = meta.get("original", field_name)
            principal = state.get_actor_identity(original)
            if principal is None:
                principal = state.get_actor_identity(field_name)
            if principal is not None:
                target = original if original in bound_payload or field_name not in bound_payload else field_name
                bound_payload[target] = principal
        return bound_payload

    def prepare_request(self, api_node: Dict, current_state: StateStore,
                        payload: Dict[str, Any], payload_source: str = "NONE") -> PreparedRequest:
        """Split a generated payload into path/query/header/cookie/body locations."""
        api_id = api_node.get("id", "unknown_api")
        method = api_node.get("method", "GET").upper()
        path = api_node.get("path", "/")
        content_type = api_node.get("content_type", "application/json")
        headers: Dict[str, str] = {}
        query_params: Dict[str, Any] = {}
        stored_cookies = current_state.get("auth_cookies", {})
        cookies: Dict[str, Any] = dict(stored_cookies) if isinstance(stored_cookies, dict) else {}
        self._apply_auth_transports(api_node, current_state, headers, query_params, cookies)
        body: Dict[str, Any] = {}

        inputs = api_node.get("inputs", {}) or {}

        def _meta_for(payload_key: str) -> Dict[str, Any]:
            direct = inputs.get(payload_key)
            if isinstance(direct, dict):
                return direct
            for field_name, meta in inputs.items():
                if not isinstance(meta, dict):
                    continue
                if meta.get("original", field_name) == payload_key:
                    return meta
            return {}

        for key, value in (payload or {}).items():
            meta = _meta_for(key)
            default_location = "query" if method in ("GET", "DELETE", "HEAD") else "body"
            location = str(meta.get("in", default_location)).lower()
            original = meta.get("original", key)
            if location == "path":
                continue
            if location == "query":
                query_params[original] = value
            elif location == "header":
                headers[str(original)] = str(value)
            elif location == "cookie":
                cookies[str(original)] = value
            else:
                body[original] = value

        url = self._build_url(path, api_node, current_state, payload or {})
        split = urlsplit(url)
        embedded_query = dict(parse_qsl(split.query, keep_blank_values=True))
        if embedded_query:
            embedded_query.update(query_params)
            query_params = embedded_query
            url = urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))

        prepared = PreparedRequest(
            api_id=api_id,
            method=method,
            url=url,
            headers=headers,
            query_params=query_params,
            cookies=cookies,
            payload_source=payload_source,
        )
        if body:
            if content_type == "application/x-www-form-urlencoded":
                prepared.form_body = body
            elif content_type == "multipart/form-data":
                prepared.form_body = {}
                prepared.files = {}
                for field_name, value in body.items():
                    meta = _meta_for(field_name)
                    if meta.get("is_file"):
                        artifact = self.artifact_provider.resolve(field_name, meta, value)
                        prepared.files[field_name] = (
                            artifact.filename, artifact.content, artifact.content_type
                        )
                        prepared.file_metadata[field_name] = artifact.metadata()
                    else:
                        prepared.form_body[field_name] = value
            elif any(_meta_for(k).get("is_file") for k in body):
                field_name, value = next(
                    (k, v) for k, v in body.items() if _meta_for(k).get("is_file")
                )
                meta = _meta_for(field_name)
                artifact = self.artifact_provider.resolve(field_name, meta, value)
                prepared.raw_body = artifact.content
                prepared.file_metadata[field_name] = artifact.metadata()
                prepared.headers["Content-Type"] = content_type
            else:
                prepared.json_body = body
        return prepared


    def _build_url(self, path: str, api_node: Dict, state: StateStore, payload: Dict) -> str:
        def _norm(s: str) -> str:
            return re.sub(r'[_\-\.\s]', '', str(s)).lower()

        def _replace(m):
            param      = m.group(1)
            param_norm = _norm(param)
            
            # 1. Exact norm match trong payload đã được canonicalize. Đây là
            # nguồn cuối cùng sau principal binding / dependency resolution.
            for k, v in payload.items():
                if _norm(k) == param_norm:
                    return str(v)

            # 2. Fallback sang StateStore khi payload không chứa path param.
            for k, v in state.memory.items():
                if _norm(k) == param_norm:
                    return str(v)
            
            # 3. Contextual ID match (ĐÂY LÀ BƯỚC MỚI)
            # {postId} → param_norm = "postid"
            # Tìm state key có dạng "post_id" hoặc "postid" 
            # bằng cách tách param thành (resource, "id"):
            #   "postId" → ("post", "id") → tìm state["post_id"]
            #   "vehicleId" → ("vehicle", "id") → tìm state["vehicle_id"]
            id_match = re.match(r'^(.+?)(id|_id)$', param_norm)
            if id_match:
                resource_part = id_match.group(1).rstrip("_")
                # Tìm key dạng "{resource}_id" hoặc "{resource}id" trong state
                for k, v in state.memory.items():
                    k_norm = _norm(k)
                    if isinstance(v, (str, int)) and v:
                        # Match: "post_id" == "post_id", hoặc "postid" == "postid"
                        if k_norm == f"{resource_part}id" or k_norm == f"{resource_part}_id":
                            log.info(f"[URL] Contextual match {{{param}}} ← state['{k}'] = {repr(str(v))[:40]}")
                            return str(v)
            
            # 4. Scored partial match (thay vì first-match-wins, chấm điểm để chọn best match)
            candidates = []
            for k, v in state.memory.items():
                if isinstance(v, (str, int)) and v:
                    k_norm = _norm(k)
                    if param_norm in k_norm or k_norm in param_norm:
                        # Tính điểm: exact substring match dài hơn → score cao hơn
                        # Tránh trường hợp key "id" (2 ký tự) match bất kỳ param nào chứa "id"
                        score = len(k_norm) / max(len(param_norm), 1)
                        # Penalty nặng cho key quá ngắn ("id" chỉ 2 ký tự → dễ match nhầm)
                        if len(k_norm) <= 2:
                            score *= 0.1
                        candidates.append((score, k, v))
            
            if candidates:
                # Chọn candidate có score cao nhất (match dài nhất, cụ thể nhất)
                candidates.sort(key=lambda x: x[0], reverse=True)
                best_score, best_k, best_v = candidates[0]
                log.debug(f"[URL] Best partial match {{{param}}} ← state['{best_k}'] = {repr(str(best_v))[:40]} (score={best_score:.2f})")
                return str(best_v)
            
            log.warning(
                f"[URL] ⚠️ Không resolve được path param {{{param}}} — "
                f"dùng sentinel '1'. Có thể gây false positive nếu resource ID=1 tồn tại!"
            )
            return "1"

        resolved = re.sub(r"\{([^}]+)\}", _replace, path)
        return f"{self.base_url}{resolved}"

    def _build_headers(self, state: StateStore) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        token = state.get("auth_token")
        if token:
            header_name   = state.get("auth_header_name", "Authorization")
            header_prefix = state.get("auth_header_prefix") or "Token"  # Mặc định Token, không đoán mò
            log.debug("[Header] applying %s authentication header", header_name)
            # Luôn tôn trọng cấu hình prefix — không còn heuristic Bearer/Token dựa vào format token
            headers[header_name] = f"{header_prefix.rstrip()} {token}"
        return headers

    def _apply_auth_transports(self, api_node: Dict, state: StateStore,
                               headers: Dict, query: Dict, cookies: Dict) -> None:
        """Apply actor-scoped auth without assumptions about JWT/Bearer."""
        applied = set()
        for transport in state.get_auth_transports():
            key = (transport.kind, transport.name)
            applied.add(key)
            value = transport.value
            if transport.kind == "cookie":
                cookies[transport.name] = value
            elif transport.kind == "query":
                query[transport.name] = value
            elif transport.kind == "header":
                headers[transport.name] = (
                    f"{transport.prefix.rstrip()} {value}".strip()
                    if transport.prefix else str(value)
                )

        # An OpenAPI apiKey scheme may name a state value directly (including
        # legacy query credentials such as openId). Only declared schemes are
        # eligible; arbitrary response fields are never appended to URLs.
        for declared in api_node.get("declared_auth_transports", []) or []:
            kind = str(declared.get("kind", "")).lower()
            name = str(declared.get("name", ""))
            if not name or (kind, name) in applied:
                continue
            value = state.get(name)
            if value is None:
                continue
            prefix = str(declared.get("prefix", ""))
            if kind == "cookie": cookies[name] = value
            elif kind == "query": query[name] = value
            elif kind == "header": headers[name] = f"{prefix} {value}".strip()

    def _fire_request(self, method: str, url: str, headers: Dict,
                      payload: Dict, content_type: str = "application/json") -> Optional[requests.Response]:
        """Backward-compatible wrapper for callers/tests using the old API."""
        prepared = PreparedRequest(
            api_id="legacy",
            method=method,
            url=url,
            headers=headers,
            payload_source="LEGACY",
        )
        if payload:
            if content_type == "application/x-www-form-urlencoded":
                prepared.form_body = payload
            elif content_type == "multipart/form-data":
                prepared.files = {k: (None, str(v)) for k, v in payload.items()}
            elif method.upper() in ("GET", "DELETE", "HEAD"):
                prepared.query_params = payload
            else:
                prepared.json_body = payload
        return self._fire_prepared_request(prepared)

    def _fire_prepared_request(self, prepared: PreparedRequest) -> Optional[requests.Response]:
        try:
            req_kwargs = {
                "method": prepared.method,
                "url": prepared.url,
                "headers": dict(prepared.headers),
                "timeout": REQUEST_TIMEOUT,
                "allow_redirects": False,
            }
            if prepared.query_params:
                req_kwargs["params"] = prepared.query_params
            if prepared.cookies:
                req_kwargs["cookies"] = prepared.cookies
            if prepared.files is not None:
                # requests must generate the multipart boundary itself.
                req_kwargs["headers"].pop("Content-Type", None)
                req_kwargs["files"] = prepared.files
                if prepared.form_body:
                    req_kwargs["data"] = prepared.form_body
            elif prepared.raw_body is not None:
                req_kwargs["data"] = prepared.raw_body
            elif prepared.form_body is not None:
                req_kwargs["data"] = prepared.form_body
            elif prepared.json_body is not None:
                req_kwargs["json"] = prepared.json_body

            # StateStore is the only cookie source. A shared Session cookie jar
            # would leak owner_a's session into user_b requests.
            self._session.cookies.clear()
            # Keep Set-Cookie values local to this request chain. The session
            # jar is deliberately cleared between actors, but a form login
            # commonly redirects to a page that still needs the new session.
            redirect_cookies = dict(req_kwargs.get("cookies") or {})
            resp = self._session.request(**req_kwargs)
            response_cookie_jar = getattr(resp, "cookies", None)
            if response_cookie_jar is not None and hasattr(response_cookie_jar, "get_dict"):
                redirect_cookies.update(response_cookie_jar.get_dict() or {})
            original_origin = self._origin(prepared.url)
            redirect_count = 0
            while self._is_redirect(resp):
                location = str((getattr(resp, "headers", {}) or {}).get("Location", ""))
                if not location:
                    break
                redirect_url = urljoin(str(req_kwargs["url"]), location)
                if self._origin(redirect_url) != original_origin:
                    log.warning("[HTTP] Refusing cross-origin redirect from %s to %s", req_kwargs["url"], redirect_url)
                    break
                redirect_count += 1
                if redirect_count > MAX_SAME_ORIGIN_REDIRECTS:
                    log.warning("[HTTP] Redirect limit exceeded for %s", prepared.url)
                    break

                req_kwargs["url"] = redirect_url
                req_kwargs.pop("params", None)
                if int(resp.status_code) == 303 or (
                    int(resp.status_code) in (301, 302)
                    and str(req_kwargs["method"]).upper() == "POST"
                ):
                    req_kwargs["method"] = "GET"
                    for body_key in ("json", "data", "files"):
                        req_kwargs.pop(body_key, None)
                    req_kwargs["headers"].pop("Content-Type", None)
                if redirect_cookies:
                    req_kwargs["cookies"] = dict(redirect_cookies)
                self._session.cookies.clear()
                resp = self._session.request(**req_kwargs)
                response_cookie_jar = getattr(resp, "cookies", None)
                if response_cookie_jar is not None and hasattr(response_cookie_jar, "get_dict"):
                    redirect_cookies.update(response_cookie_jar.get_dict() or {})
            # The final response may not repeat the cookie set by the initial
            # redirect. Attach the local chain cookies so the caller can store
            # the authenticated session in StateStore.
            if redirect_cookies:
                response_cookie_jar = getattr(resp, "cookies", None)
                if response_cookie_jar is not None and hasattr(response_cookie_jar, "set"):
                    existing = response_cookie_jar.get_dict() if hasattr(response_cookie_jar, "get_dict") else {}
                    for cookie_name, cookie_value in redirect_cookies.items():
                        if cookie_name not in existing:
                            response_cookie_jar.set(cookie_name, cookie_value)
            self._session.cookies.clear()
            return resp
        except requests.exceptions.Timeout:
            log.error(f"[HTTP] Timeout after {REQUEST_TIMEOUT}s — {prepared.url}")
        except requests.exceptions.ConnectionError as e:
            log.error(f"[HTTP] ConnectionError — {e}")
        except requests.exceptions.RequestException as e:
            log.error(f"[HTTP] RequestException — {e}")
        return None

    @staticmethod
    def _origin(url: str):
        parsed = urlsplit(str(url))
        default_port = 443 if parsed.scheme.casefold() == "https" else 80
        return parsed.scheme.casefold(), (parsed.hostname or "").casefold(), parsed.port or default_port

    @staticmethod
    def _is_redirect(response) -> bool:
        return int(getattr(response, "status_code", 0) or 0) in (301, 302, 303, 307, 308)

    @staticmethod
    def _failure_result(api_id: str, edge_failure: bool) -> Dict:
        return {
            "status":           0,
            "successful":       False,
            "semantic_failure": False,
            "outcome_reason":   "Network request failed",
            "server_error":     False,
            "auth_anomaly":     False,
            "pii_leakage":      False,
            "state_transition": False,
            "response_diff":    False,
            "edge_failure":     edge_failure,
            "anomaly_details":  [f"Request to {api_id} failed (network error)"],
            "raw_response":     None,
            "response_text":    "",
            "sent_payload":     {},
        }

    @staticmethod
    def _status_color(status: int) -> str:
        if status >= 500: return "\033[91m\033[1m"
        if status >= 400: return "\033[93m"
        if status >= 200: return "\033[92m"
        return "\033[0m"
