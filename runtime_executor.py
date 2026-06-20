import json
import re
import uuid
import logging
import requests
import hashlib
from typing import Any, Dict, Optional

from state_store import StateStore
from llm_planner import LLMPlanner

log = logging.getLogger("executor")
REQUEST_TIMEOUT = 10

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

    def analyze(self, response: requests.Response, state: StateStore,
                sent_payload: Dict) -> Dict[str, Any]:
        status     = response.status_code
        body_text  = response.text
        result     = {
            "server_error":   False,
            "auth_anomaly":   False,
            "pii_leakage":    False,
            "anomaly_details": [],
        }

        if status >= 500:
            result["server_error"] = True
            result["anomaly_details"].append(f"HTTP {status} — possible crash/unhandled exception")
            log.error(f"\033[91m[!!!] SERVER ERROR {status}\033[0m — possible vulnerability!")

        if status == 200:
            has_token = state.has("auth_token")
            # Cải thiện keyword nhạy cảm tổng quát hơn cho nhiều hệ thống
            sensitive_keywords = r"admin|account|profile|order|vehicle|payment|salary|secret|invoice|wallet|setting"
            if not has_token and re.search(sensitive_keywords, body_text, re.I):
                result["auth_anomaly"] = True
                result["anomaly_details"].append("Auth Bypass: 200 on sensitive endpoint without token")
                log.warning(f"\033[93m[AUTH BYPASS]\033[0m 200 received without auth_token in state")

            own_user_id = state.get("user_id")
            if own_user_id and sent_payload:
                for k, v in sent_payload.items():
                    if re.search(r"user_?id|owner_?id|account_?id", k, re.I):
                        if str(v) != str(own_user_id):
                            result["auth_anomaly"] = True
                            result["anomaly_details"].append(
                                f"Potential IDOR: sent {k}={v}, own id={own_user_id}, got 200"
                            )
                            log.warning(f"\033[93m[IDOR]\033[0m Accessed resource with foreign ID {k}={v}")

        if not state.has("auth_token"):
            emails_found = self._EMAIL_RE.findall(body_text)
            phones_found = self._PHONE_RE.findall(body_text)
            if emails_found or phones_found:
                result["pii_leakage"] = True
                result["anomaly_details"].append(
                    f"PII Leakage (no auth): emails={emails_found[:3]}, phones={phones_found[:3]}"
                )
                log.warning(f"\033[93m[PII LEAK]\033[0m Found PII in unauthenticated response")

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
                        edge_deps: Optional[list] = None) -> Dict[str, Any]:
        api_id  = api_node.get("id", "unknown_api")
        method  = api_node.get("method", "GET").upper()

        sent_payload, payload_source = self.planner.generate_payload(api_node, current_state, edge_deps=edge_deps)
        
        # 1. Thực thi lần đầu
        exec_result = self._do_execute(api_node, current_state, sent_payload, payload_source)
        
        # 2. Vòng lặp Self-Healing (Tự phục hồi lỗi)
        # Chỉ áp dụng nếu lỗi >= 400 và method cho phép thay đổi body payload
        if exec_result["status"] >= 400 and method in ("POST", "PUT", "PATCH") and exec_result["response_text"]:
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
                
                budget_key = f"{api_id}:{curr_status}"
                max_repairs_allowed = 1 if curr_status >= 500 else 3
                
                # Rule 1 & 3: Giới hạn số lần repair tổng cộng trong toàn bộ phiên fuzzing (500 chỉ cho 1 lần)
                if self._repair_budget.get(budget_key, 0) >= max_repairs_allowed:
                    log.info(f"\033[90m[Repair Skip]\033[0m Global budget exhausted for {budget_key} ({max_repairs_allowed}/{max_repairs_allowed})")
                    current_exec["repair_skipped"] = True
                    break
                
                # Invalidate schema cache khi phát hiện lỗi trùng lặp (nhiều biến thể)
                response_text = current_exec.get("response_text", "")
                if DUPLICATE_RE.search(response_text):
                    self.planner._schema_cache.pop(api_node.get("id"), None)
                    self.planner._payload_cache.clear()  # xóa cả payload cache để LLM bắt buộc sinh mới
                    log.info(f"[Cache Invalidate] Cleared ALL caches for {api_id} — duplicate/conflict detected: {response_text[:80]}")

                # Rule 2: Chống repair trùng lặp cùng một payload trong cùng 1 lần execute_request
                payload_str = json.dumps(current_payload, sort_keys=True)
                payload_hash = hashlib.md5(payload_str.encode('utf-8')).hexdigest()
                seen_key = f"{budget_key}:{payload_hash}"
                
                if seen_key in _local_seen:   # chỉ check trong local scope
                    log.info(f"\033[90m[Repair Skip]\033[0m Duplicate payload signature for {seen_key}")
                    current_exec["repair_skipped"] = True
                    break
                    
                # Trừ đi 1 lượt sử dụng
                _local_seen.add(seen_key)     # chỉ add vào local
                self._repair_budget[budget_key] = self._repair_budget.get(budget_key, 0) + 1

                log.warning(f"\033[93m[Self-Healing]\033[0m API {api_id} returned {curr_status}. Triggering LLM repair (Attempt {attempt+1}/3)...")
                repaired_payload = self.planner.repair_payload(
                    api_node, current_state, current_payload, current_exec["response_text"], edge_deps
                )
                
                if not repaired_payload:
                    break
                    
                exec_result_new = self._do_execute(api_node, current_state, repaired_payload, "LLM_REPAIR")
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

        url     = self._build_url(path, api_node, current_state, sent_payload)
        headers = self._build_headers(current_state)
        content_type = api_node.get("content_type", "application/json")

        log.info(f"\033[96m[>>]\033[0m {method} {url}  payload={json.dumps(sent_payload, ensure_ascii=False)[:120]}")

        response = self._fire_request(method, url, headers, sent_payload, content_type)

        if response is None:
            log.error(f"\033[91m[!!] Request failed (timeout/connection)\033[0m for {api_id}")
            return self._failure_result(api_id, edge_failure=False)

        status = response.status_code
        if status == 400:
            log.warning(f"\033[93m[400 Debug]\033[0m Server message: {response.text}")
        log.info(f"{self._status_color(status)}[<<]\033[0m {status} {api_id} ({len(response.text)} bytes)")

        try:
            response_json = response.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            response_json = None

        anomaly = self.analyzer.analyze(response, current_state, sent_payload)

        state_transition = False
        if response_json and status in (200, 201, 202):
            state_transition = current_state.extract_from_response(
                response_json,
                schema=api_node.get("outputs", {})
            )

        edge_failure = (status == 400)

        if edge_failure:
            log.warning(f"\033[93m[EDGE FAIL]\033[0m 400 on {api_id} — penalizing ODG edge (bad schema/FK)")

        return {
            "status":          status,
            "server_error":    anomaly["server_error"],
            "auth_anomaly":    anomaly["auth_anomaly"],
            "pii_leakage":     anomaly["pii_leakage"],
            "state_transition": state_transition,
            "response_diff":   anomaly["pii_leakage"] or anomaly["server_error"],
            "edge_failure":    edge_failure,
            "anomaly_details": anomaly["anomaly_details"],
            "raw_response":    response_json,
            "response_text":   response.text if hasattr(response, 'text') else "",
            "sent_payload":    sent_payload,
            "sent_headers":    headers,
            "payload_source":  payload_source,
            "url":             url,
        }


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
            
            # 3. Partial match: state key contains param name (vd: "book_title" chứa "title")
            for k, v in state.memory.items():
                if isinstance(v, (str, int)) and v:
                    if param_norm in _norm(k) or _norm(k) in param_norm:
                        log.debug(f"[URL] Partial match {{{param}}} ← state['{k}'] = {repr(str(v))[:40]}")
                        return str(v)
            
            log.debug(f"[URL] No match for {{{param}}} — using sentinel '1'")
            return "1"

        resolved = re.sub(r"\{([^}]+)\}", _replace, path)
        return f"{self.base_url}{resolved}"

    def _build_headers(self, state: StateStore) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        token = state.get("auth_token")
        if token:
            header_name   = state.get("auth_header_name", "Authorization")
            header_prefix = state.get("auth_header_prefix") or "Token"  # Mặc định Token, không đoán mò
            log.warning(f"[DEBUG] prefix={repr(header_prefix)} token[:10]={repr(str(token)[:10])}")
            # Luôn tôn trọng cấu hình prefix — không còn heuristic Bearer/Token dựa vào format token
            headers[header_name] = f"{header_prefix.rstrip()} {token}"
        return headers

    def _fire_request(self, method: str, url: str, headers: Dict,
                      payload: Dict, content_type: str = "application/json") -> Optional[requests.Response]:
        try:
            req_kwargs = {
                "method": method,
                "url": url,
                "headers": headers,
                "timeout": REQUEST_TIMEOUT,
                "allow_redirects": True
            }
            
            if payload:
                if content_type == "application/x-www-form-urlencoded":
                    req_kwargs["data"] = payload
                elif content_type == "multipart/form-data":
                    # requests tự thêm header multipart boundary khi có files
                    req_kwargs["files"] = {k: (None, str(v)) for k, v in payload.items()}
                else:
                    req_kwargs["json"] = payload
                    
            resp = self._session.request(**req_kwargs)
            return resp
        except requests.exceptions.Timeout:
            log.error(f"[HTTP] Timeout after {REQUEST_TIMEOUT}s — {url}")
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
