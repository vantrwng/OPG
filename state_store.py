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
    }

    # Pattern nhận diện các ID chung (id, uuid, ref, code)
    _GENERIC_ID_PATTERN = re.compile(r"(_id|Id|uuid|_ref|Ref|_code|Code)$", re.I)

    def __init__(self, initial_state: Optional[Dict[str, Any]] = None):
        self.memory: Dict[str, Any] = initial_state if initial_state else {}

    # ── Basic CRUD ──────────────────────────────────────────────────────────

    def update(self, key: str, value: Any) -> None:
        self.memory[key] = value
        log.debug(f"\033[96m[State] SET\033[0m {key} = {repr(value)[:80]}")

    def get(self, key: str, default: Any = None) -> Any:
        return self.memory.get(key, default)

    def has(self, key: str) -> bool:
        return key in self.memory

    def clone(self) -> "StateStore":
        """Deep copy — dùng khi Beam Search tạo nhánh mới."""
        return StateStore(copy.deepcopy(self.memory))

    # ── Smart Extraction ────────────────────────────────────────────────────

    def extract_from_response(self, response_json: Any, schema: Optional[Dict] = None) -> bool:
        """
        Duyệt đệ quy response JSON, so khớp với _HARVEST_PATTERNS,
        tự động ghi vào memory.

        Returns True nếu có ít nhất 1 trường mới được harvest.
        """
        if not isinstance(response_json, dict):
            # Thử unwrap nếu response là list[dict]
            if isinstance(response_json, list) and response_json:
                response_json = response_json[0]
            else:
                return False

        found_new = False
        for resp_key, resp_val in response_json.items():
            if not isinstance(resp_key, str):
                continue
                
            matched = False
            # 1. So khớp core pattern
            for state_key, pattern in self._HARVEST_PATTERNS.items():
                if pattern.search(resp_key):
                    if resp_val and resp_val != self.memory.get(state_key):
                        self.update(state_key, resp_val)
                        found_new = True
                    matched = True
                    break
                    
            # 2. So khớp generic pattern cho các loại ID
            if not matched and self._GENERIC_ID_PATTERN.search(resp_key):
                # Lưu state_key dựa trên chính tên biến trả về
                # ví dụ: "patientId" -> "patientId"
                if resp_val and resp_val != self.memory.get(resp_key):
                    self.update(resp_key, resp_val)
                    found_new = True
                    
            # 3. Đệ quy vào nested object
            if isinstance(resp_val, dict):
                if self.extract_from_response(resp_val):
                    found_new = True
            elif isinstance(resp_val, list):
                for item in resp_val:
                    if isinstance(item, dict):
                        if self.extract_from_response(item):
                            found_new = True

        return found_new

    def __repr__(self) -> str:
        safe = {k: (str(v)[:40] + "...") if len(str(v)) > 40 else v
                for k, v in self.memory.items()}
        return f"StateStore({safe})"
