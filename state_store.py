import re
import copy
import logging
from typing import Any, Dict, Optional

log = logging.getLogger("executor")

class StateStore:
    """
    Bộ nhớ ngữ cảnh (Context Memory) cho một beam/path đang thực thi.

    Lưu trữ các cặp key-value thu thập được trong suốt chuỗi API:
      - auth_token, refresh_token
      - user_id, vehicle_id, order_id, ...
      - email, phone, ...

    clone() → deep copy để Beam Search rẽ nhánh mà không bị đè dữ liệu.
    """

    # Pattern nhận diện các trường quan trọng cần harvest từ response
    # Core patterns cho các field quan trọng đặc biệt
    _HARVEST_PATTERNS: Dict[str, re.Pattern] = {
        "auth_token":    re.compile(r"(token|access_token|jwt|bearer)$", re.I),
        "refresh_token": re.compile(r"refresh_token", re.I),
        "email":         re.compile(r"^email$", re.I),
        "phone":         re.compile(r"phone|mobile|contact_?no", re.I),
        "user_role":     re.compile(r"^(role|userRole|user_role|accountType)$", re.I),
    }

    # Các key cấu hình không được phép bị ghi đè bởi fallback harvest
    _PROTECTED_KEYS = frozenset({"auth_header_name", "auth_header_prefix"})

    # Regex để strip tiền tố "Bearer " / "Token " khỏi token trước khi lưu vào state
    _TOKEN_PREFIX_RE = re.compile(r"^(Bearer|Token)\s+", re.I)

    # Pattern nhận diện các ID chung (id, uuid, ref, code)
    _GENERIC_ID_PATTERN = re.compile(r"(_id|Id|uuid|_ref|Ref|_code|Code)$", re.I)

    def __init__(self, initial_state: Optional[Dict[str, Any]] = None):
        self.memory: Dict[str, Any] = initial_state if initial_state else {}
        # Lưu baseline response (response hợp lệ) cho mỗi API, dùng bởi Auditor Agent
        self._baseline_responses: Dict[str, Any] = {}

    # ── Basic CRUD ──────────────────────────────────────────────────────────

    def update(self, key: str, value: Any) -> None:
        # Không cho phép ghi đè các key cấu hình hệ thống một khi đã được khởi tạo
        if key in self._PROTECTED_KEYS and key in self.memory:
            log.debug(f"[State] PROTECTED KEY '{key}' bị block ghi đè (giá trị hiện tại: {repr(self.memory[key])[:40]})")
            return
        self.memory[key] = value
        log.debug(f"\033[96m[State] SET\033[0m {key} = {repr(value)[:80]}")

    def get(self, key: str, default: Any = None) -> Any:
        return self.memory.get(key, default)

    def has(self, key: str) -> bool:
        return key in self.memory

    def clone(self) -> "StateStore":
        """Deep copy — dùng khi Beam Search tạo nhánh mới."""
        new_store = StateStore(copy.deepcopy(self.memory))
        new_store._baseline_responses = copy.deepcopy(self._baseline_responses)
        return new_store

    # ── Baseline Storage (dùng bởi Auditor Agent) ───────────────────────────

    def set_baseline(self, api_id: str, exec_result: Any) -> None:
        """
        Lưu exec_result của request hợp lệ làm baseline để Auditor so sánh.
        Chỉ lưu nếu chưa có baseline cho api_id này (baseline = lần đầu thành công).
        """
        if api_id not in self._baseline_responses:
            self._baseline_responses[api_id] = exec_result
            log.debug(f"[State] BASELINE SET for {api_id}")

    def get_baseline(self, api_id: str) -> Optional[Any]:
        """Lấy baseline exec_result cho api_id. Trả về None nếu chưa có."""
        return self._baseline_responses.get(api_id)

    # ── Smart Extraction ────────────────────────────────────────────────────

    def extract_from_response(self, response_json: Any, schema: Optional[Dict] = None) -> bool:
        """
        Duyệt đệ quy response JSON, so khớp với _HARVEST_PATTERNS,
        tự động ghi vào memory.
        Nếu có schema guide (output fields từ OpenAPI spec) → harvest thêm theo tên field.
        Flatten response trước khi so khớp để xử lý nested wrapper (vd: {"Books": [{...}]}).

        Returns True nếu có ít nhất 1 trường mới được harvest.
        """
        if not isinstance(response_json, dict):
            # Thử unwrap nếu response là list[dict]
            if isinstance(response_json, list) and response_json:
                response_json = response_json[0]
            else:
                return False

        found_new = False

        # ── Bước 1: Harvest theo Pattern (giữ nguyên logic cũ) ──────────────
        for resp_key, resp_val in response_json.items():
            if not isinstance(resp_key, str):
                continue
                
            matched = False
            # 1a. So khớp core pattern
            for state_key, pattern in self._HARVEST_PATTERNS.items():
                if pattern.search(resp_key):
                    if resp_val and resp_val != self.memory.get(state_key):
                        # Strip tiền tố "Bearer "/"Token " nếu server trả về token đã gắn sẵn prefix
                        if state_key == "auth_token" and isinstance(resp_val, str):
                            resp_val = self._TOKEN_PREFIX_RE.sub("", resp_val).strip()
                        self.update(state_key, resp_val)
                        found_new = True
                    matched = True
                    break
                    
            # 1b. So khớp generic pattern cho các loại ID
            if not matched and self._GENERIC_ID_PATTERN.search(resp_key):
                if resp_val and resp_val != self.memory.get(resp_key):
                    self.update(resp_key, resp_val)
                    found_new = True
                    
            # 1c. Đệ quy vào nested object
            if isinstance(resp_val, dict):
                if self.extract_from_response(resp_val):
                    found_new = True
            elif isinstance(resp_val, list):
                for item in resp_val:
                    if isinstance(item, dict):
                        if self.extract_from_response(item):
                            found_new = True

        # ── Bước 2: Schema-guided harvest (dùng output spec làm guide) ──────
        # Flatten toàn bộ response (kể cả nested) để so khớp với spec fields
        flat = self._flatten(response_json)

        if schema:
            for field_key, field_meta in schema.items():
                orig = field_meta.get("original", field_key) \
                       if isinstance(field_meta, dict) else field_key
                if orig in flat:
                    val = flat[orig]
                    if isinstance(val, (str, int)) and val and val != self.memory.get(orig):
                        self.update(orig, val)
                        log.debug(f"\033[96m[State] SCHEMA-HARVEST\033[0m {orig} = {repr(val)[:60]}")
                        found_new = True

        # ── Bước 3: Fallback — harvest toàn bộ leaf string từ flat (kể cả nested array) ──
        # Giúp tóm các field quan trọng không được khai báo rõ trong spec
        for k, v in flat.items():
            if not isinstance(k, str) or not isinstance(v, (str, int)):
                continue
            if not v or v == self.memory.get(k):
                continue
            # Không được ghi đè các key cấu hình hệ thống (bảo vệ auth_header_prefix, ...)
            if k in self._PROTECTED_KEYS:
                continue
            # Chỉ harvest nếu chưa được lưu bởi bước 1 (pattern harvest)
            if k not in self.memory:
                self.update(k, v)
                found_new = True

        return found_new

    @staticmethod
    def _flatten(obj, result=None):
        """Flatten nested dict/list thành dict phẳng để harvest field ở mọi level."""
        if result is None:
            result = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (str, int, float)) and v != "" and v is not None:
                    result[k] = v
                elif isinstance(v, dict):
                    StateStore._flatten(v, result)
                elif isinstance(v, list):
                    for item in v:
                        StateStore._flatten(item, result)
        elif isinstance(obj, list):
            for item in obj:
                StateStore._flatten(item, result)
        return result

    def __repr__(self) -> str:
        safe = {k: (str(v)[:40] + "...") if len(str(v)) > 40 else v
                for k, v in self.memory.items()}
        return f"StateStore({safe})"
