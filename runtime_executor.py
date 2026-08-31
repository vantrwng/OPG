import json
import re
import uuid
import logging
import requests
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from state_store import StateStore
from llm_planner import LLMPlanner

log = logging.getLogger("executor")
REQUEST_TIMEOUT = 10


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
            "has_token": state.has("auth_token"),
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
    def __init__(self, base_url: str, planner: LLMPlanner, knowledge_memory=None):
        self.base_url        = base_url.rstrip("/")
        self.planner         = planner
        self.analyzer        = FeedbackAnalyzer()
        self.memory          = knowledge_memory # Có thể dùng để ghi log requests
        self._session        = requests.Session()
        self._session.headers.update({"Accept": "application/json, */*"})
        
        # State tracking cho Repair để tránh gọi LLM vô tận
        self._repair_budget = {}  # key: f"{api_id}:{status}", value: int
        self._repair_seen = set() # key: f"{api_id}:{status}:{hash(payload)}"

    def execute_request(self, api_node: Dict, current_state: StateStore,
                        edge_deps: Optional[list] = None,
                        payload_override: Optional[Dict[str, Any]] = None,
                        payload_source_override: Optional[str] = None,
                        allow_repair: bool = True) -> Dict[str, Any]:
        api_id  = api_node.get("id", "unknown_api")
        method  = api_node.get("method", "GET").upper()

        if payload_override is None:
            sent_payload, payload_source = self.planner.generate_payload(
                api_node, current_state, edge_deps=edge_deps
            )
        else:
            sent_payload = dict(payload_override)
            payload_source = payload_source_override or "EXPLICIT_OVERRIDE"
        
        # 1. Thực thi lần đầu
        exec_result = self._do_execute(api_node, current_state, sent_payload, payload_source)
        
        # 2. Vòng lặp Self-Healing (Tự phục hồi lỗi)
        # Chỉ áp dụng nếu lỗi >= 400 và method cho phép thay đổi body payload
        if (allow_repair and exec_result["status"] >= 400
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
                
                if exec_result_new["status"] < 400:
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

    def _do_execute(self, api_node: Dict, current_state: StateStore, sent_payload: Dict, payload_source: str) -> Dict[str, Any]:
        api_id  = api_node.get("id", "unknown_api")
        method  = api_node.get("method", "GET").upper()
        path    = api_node.get("path", "/")

        prepared = self.prepare_request(
            api_node=api_node,
            current_state=current_state,
            payload=sent_payload,
            payload_source=payload_source,
        )
        url = prepared.url
        headers = prepared.headers

        log.info(f"\033[96m[>>]\033[0m {method} {url}  payload={json.dumps(sent_payload, ensure_ascii=False)[:120]}")

        response = self._fire_prepared_request(prepared)

        if response is None:
            log.error(f"\033[91m[!!] Request failed (timeout/connection)\033[0m for {api_id}")
            return self._failure_result(api_id, edge_failure=False)

        status = response.status_code
        if status == 400:
            log.warning(f"\033[93m[400 Debug]\033[0m Server message: {response.text}")
        log.info(f"{self._status_color(status)}[<<]\033[0m {status} {api_id} ({len(response.text)} bytes)")
        log.debug(f"\033[90m[RAW RESPONSE]\033[0m {response.text[:500]}")

        try:
            response_json = response.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            response_json = None

        anomaly = self.analyzer.analyze(response, current_state, sent_payload)

        response_cookies = getattr(response, "cookies", None)
        if response_cookies is not None and hasattr(response_cookies, "get_dict"):
            cookie_dict = response_cookies.get_dict()
            if isinstance(cookie_dict, dict) and cookie_dict:
                current_state.update("auth_cookies", cookie_dict)

        state_transition = False
        if response_json and status in (200, 201, 202):
            state_transition = current_state.extract_from_response(
                response_json,
                schema=api_node.get("outputs", {}),
                api_id=api_id
            )

        # Preserve credentials from any successful signup response, including
        # HTTP 204 where there is no JSON body to harvest.
        if status in (200, 201, 202, 204):
            import re as _re
            _combined = path + " " + api_id.lower()
            _is_create = bool(_re.search(r"signup|register|create|add", _combined))
            if _is_create and sent_payload:
                for _field in (
                    "email", "username", "name", "password", "phone", "mobile", "number"
                ):
                    if _field in sent_payload and sent_payload[_field]:
                        current_state.update(_field, sent_payload[_field])
                        log.debug(f"[State] CREDENTIAL-SAVE from request: {_field} = {repr(sent_payload[_field])[:60]}")

        edge_failure = (status == 400)

        if edge_failure:
            log.warning(f"\033[93m[EDGE FAIL]\033[0m 400 on {api_id} — penalizing ODG edge (bad schema/FK)")

        return {
            "status":          status,
            "server_error":    anomaly.get("server_error", False),
            "auth_anomaly":    False,  # Bỏ heuristic cứng, dời sang LLM Auditor
            "pii_leakage":     len(anomaly.get("extracted_emails", [])) > 0 or len(anomaly.get("extracted_phones", [])) > 0,
            "state_transition": state_transition,
            "response_diff":   anomaly.get("server_error", False),
            "edge_failure":    edge_failure,
            "anomaly_details": anomaly.get("anomaly_details", []),
            "raw_response":    response_json,
            "response_text":   response.text if hasattr(response, 'text') else "",
            "sent_payload":    sent_payload,
            "sent_headers":    headers,
            "sent_query":      prepared.query_params,
            "sent_cookies":    prepared.cookies,
            "actor_id":        current_state.get("actor_id", "default"),
            "payload_source":  payload_source,
            "url":             url,
        }

    def prepare_request(self, api_node: Dict, current_state: StateStore,
                        payload: Dict[str, Any], payload_source: str = "NONE") -> PreparedRequest:
        """Split a generated payload into path/query/header/cookie/body locations."""
        api_id = api_node.get("id", "unknown_api")
        method = api_node.get("method", "GET").upper()
        path = api_node.get("path", "/")
        content_type = api_node.get("content_type", "application/json")
        headers = self._build_headers(current_state)
        query_params: Dict[str, Any] = {}
        stored_cookies = current_state.get("auth_cookies", {})
        cookies: Dict[str, Any] = dict(stored_cookies) if isinstance(stored_cookies, dict) else {}
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
                prepared.files = {k: (None, str(v)) for k, v in body.items()}
            else:
                prepared.json_body = body
        return prepared


    def _build_url(self, path: str, api_node: Dict, state: StateStore, payload: Dict) -> str:
        def _norm(s: str) -> str:
            return re.sub(r'[_\-\.\s]', '', str(s)).lower()

        def _replace(m):
            param      = m.group(1)
            param_norm = _norm(param)
            
            # 1. Exact norm match trong StateStore
            for k, v in state.memory.items():
                if _norm(k) == param_norm:
                    return str(v)
            
            # 2. Exact norm match trong payload
            for k, v in payload.items():
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
            log.debug(f"[Header] prefix={repr(header_prefix)} token[:10]={repr(str(token)[:10])}")
            # Luôn tôn trọng cấu hình prefix — không còn heuristic Bearer/Token dựa vào format token
            headers[header_name] = f"{header_prefix.rstrip()} {token}"
        return headers

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
                "headers": prepared.headers,
                "timeout": REQUEST_TIMEOUT,
                "allow_redirects": True
            }
            if prepared.query_params:
                req_kwargs["params"] = prepared.query_params
            if prepared.cookies:
                req_kwargs["cookies"] = prepared.cookies
            if prepared.files is not None:
                req_kwargs["files"] = prepared.files
            elif prepared.form_body is not None:
                req_kwargs["data"] = prepared.form_body
            elif prepared.json_body is not None:
                req_kwargs["json"] = prepared.json_body

            resp = self._session.request(**req_kwargs)
            return resp
        except requests.exceptions.Timeout:
            log.error(f"[HTTP] Timeout after {REQUEST_TIMEOUT}s — {prepared.url}")
        except requests.exceptions.ConnectionError as e:
            log.error(f"[HTTP] ConnectionError — {e}")
        except requests.exceptions.RequestException as e:
            log.error(f"[HTTP] RequestException — {e}")
        return None

    @staticmethod
    def _failure_result(api_id: str, edge_failure: bool) -> Dict:
        return {
            "status":           0,
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
