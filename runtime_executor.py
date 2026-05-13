import os
import json
import re
import uuid
import logging
import requests
from typing import Any, Dict, Optional

from state_store import StateStore
from llm_planner import LLMPlanner

log = logging.getLogger("executor")
REQUEST_TIMEOUT = 10

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
            if not has_token and re.search(r"admin|account|profile|order|vehicle", body_text, re.I):
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
        self._session.headers.update({"Content-Type": "application/json", "Accept": "application/json"})

    def execute_request(self, api_node: Dict, current_state: StateStore,
                        edge_deps: Optional[list] = None) -> Dict[str, Any]:
        api_id  = api_node.get("id", "unknown_api")
        method  = api_node.get("method", "GET").upper()
        path    = api_node.get("path", "/")

        sent_payload = self.planner.generate_payload(api_node, current_state, edge_deps=edge_deps)

        url     = self._build_url(path, api_node, current_state, sent_payload)
        headers = self._build_headers(current_state)

        log.info(f"\033[96m[>>]\033[0m {method} {url}  payload={json.dumps(sent_payload, ensure_ascii=False)[:120]}")

        response = self._fire_request(method, url, headers, sent_payload)

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
            state_transition = current_state.extract_from_response(response_json)

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
        }

    def _build_url(self, path: str, api_node: Dict, state: StateStore, payload: Dict) -> str:
        def _norm(s: str) -> str:
            return re.sub(r'[_\-\.\s]', '', str(s)).lower()

        def _replace(m):
            param      = m.group(1)
            param_norm = _norm(param)
            for k, v in state.memory.items():
                if _norm(k) == param_norm: return str(v)
            for k, v in payload.items():
                if _norm(k) == param_norm: return str(v)
            log.debug(f"[URL] No match for {{{param}}} — using sentinel '1'")
            return "1"

        resolved = re.sub(r"\{([^}]+)\}", _replace, path)
        return f"{self.base_url}{resolved}"

    def _build_headers(self, state: StateStore) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        token = state.get("auth_token")
        if token:
            if re.match(r"^ey", str(token)):   
                headers["Authorization"] = f"Bearer {token}"
            else:
                headers["Authorization"] = f"Token {token}"
        return headers

    def _fire_request(self, method: str, url: str, headers: Dict,
                      payload: Dict) -> Optional[requests.Response]:
        try:
            resp = self._session.request(
                method  = method,
                url     = url,
                headers = headers,
                json    = payload if payload else None,
                timeout = REQUEST_TIMEOUT,
                allow_redirects = True,
            )
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
        }

    @staticmethod
    def _status_color(status: int) -> str:
        if status >= 500: return "\033[91m\033[1m"
        if status >= 400: return "\033[93m"
        if status >= 200: return "\033[92m"
        return "\033[0m"


class BootstrapExecutor:
    SIGNUP_PATH = "/identity/api/auth/signup"
    LOGIN_PATH  = "/identity/api/auth/login"

    FIXED_EMAIL    = os.getenv("CRAPI_EMAIL")
    FIXED_NAME     = "John Doe"
    FIXED_NUMBER   = "8755050728"
    FIXED_PASSWORD = os.getenv("CRAPI_PASSWORD")

    def __init__(self, base_url: str = "http://localhost:8888"):
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept":       "application/json",
        })

    def bootstrap(self) -> StateStore:
        state = StateStore()

        if self.FIXED_EMAIL:
            email    = self.FIXED_EMAIL
            password = self.FIXED_PASSWORD
            log.info(f"\033[1m[Bootstrap]\033[0m Dùng credentials cố định: {email}")
            state.update("email",    email)
            state.update("password", password)
            state.update("name",     self.FIXED_NAME)
            state.update("number",   self.FIXED_NUMBER)

            token = self._do_login(email, password, state)
        else:
            rand_suffix = uuid.uuid4().hex[:8]
            email    = f"fuzzer_{rand_suffix}@test.com"
            password = "FuzzPass@123!"
            log.info(f"\033[1m[Bootstrap]\033[0m Auto-signup với email: {email}")
            state.update("email",    email)
            state.update("password", password)

            signup_ok = self._do_signup(email, password)
            if not signup_ok:
                log.warning(f"\033[93m[Bootstrap]\033[0m Signup không thành công — thử login thẳng")

            token = self._do_login(email, password, state)

        if not token:
            log.error(f"\033[91m[Bootstrap]\033[0m Login thất bại! Fuzzer sẽ chạy KHÔNG có auth_token.")
            return state

        log.info(f"\033[92m[Bootstrap]\033[0m ✓ auth_token = {str(token)[:50]}...")
        self._discover_resources(state)
        return state

    def _discover_resources(self, state: StateStore) -> None:
        token = state.get("auth_token")
        if not token:
            return
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        try:
            url  = f"{self.base_url}/identity/api/v2/user/dashboard"
            resp = self._session.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("id"): state.update("user_id", data["id"])
                if data.get("video_id"): state.update("video_id", data["video_id"])
                if data.get("video_name"): state.update("video_name", data["video_name"])
        except Exception as e:
            pass

        try:
            url  = f"{self.base_url}/identity/api/v2/vehicle/vehicles"
            resp = self._session.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                vehicles = resp.json()
                if isinstance(vehicles, list) and vehicles:
                    v = vehicles[0]
                    if v.get("id"): state.update("vehicle_id", v["id"])
                    if v.get("uuid"): state.update("vehicle_uuid", v["uuid"])
                    if v.get("vin"): state.update("vin", v["vin"])
                    if v.get("pincode"): state.update("pincode", v["pincode"])
                elif isinstance(vehicles, dict) and vehicles.get("vehicles"):
                    vlist = vehicles["vehicles"]
                    if vlist:
                        v = vlist[0]
                        state.update("vehicle_id", v.get("id", ""))
                        state.update("vin", v.get("vin", ""))
                        state.update("pincode", v.get("pincode", ""))
        except Exception as e:
            pass

    def _do_signup(self, email: str, password: str) -> bool:
        url     = f"{self.base_url}{self.SIGNUP_PATH}"
        payload = {"email": email, "name": "FuzzerBot", "number": "9876543210", "password": password}
        try:
            resp = self._session.post(url, json=payload, timeout=15)
            return resp.status_code in (200, 201, 400, 409)
        except requests.exceptions.RequestException:
            return False

    def _do_login(self, email: str, password: str, state: StateStore) -> Optional[str]:
        url     = f"{self.base_url}{self.LOGIN_PATH}"
        payload = {"email": email, "password": password}
        try:
            resp = self._session.post(url, json=payload, timeout=15)
            if resp.status_code not in (200, 201):
                return None
            data  = resp.json()
            token = data.get("token") or data.get("access_token") or data.get("accessToken") or data.get("jwt")
            if not token: return None

            state.update("auth_token",  token)
            state.update("token_type",  data.get("type", "Bearer"))
            state.update("user_role",   data.get("role", ""))
            return token
        except (requests.exceptions.RequestException, ValueError):
            return None