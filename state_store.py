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
    _HARVEST_PATTERNS: Dict[str, re.Pattern] = {
        "auth_token":    re.compile(r"(token|access_token|jwt|bearer)", re.I),
        "refresh_token": re.compile(r"refresh_token", re.I),
        "user_id":       re.compile(r"^(user_?id|userid|account_?id)$", re.I),
        "vehicle_id":    re.compile(r"vehicle_?id|vehicleid|vin", re.I),
        "order_id":      re.compile(r"order_?id|orderid", re.I),
        "product_id":    re.compile(r"product_?id|productid|item_?id", re.I),
        "email":         re.compile(r"^email$", re.I),
        "phone":         re.compile(r"phone|mobile|contact_?no", re.I),
    }

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
            for state_key, pattern in self._HARVEST_PATTERNS.items():
                if pattern.search(resp_key):
                    if resp_val and resp_val != self.memory.get(state_key):
                        self.update(state_key, resp_val)
                        found_new = True
                    break
            # Đệ quy vào nested object
            if isinstance(resp_val, dict):
                if self.extract_from_response(resp_val):
                    found_new = True

        return found_new

    def __repr__(self) -> str:
        safe = {k: (str(v)[:40] + "...") if len(str(v)) > 40 else v
                for k, v in self.memory.items()}
        return f"StateStore({safe})"
