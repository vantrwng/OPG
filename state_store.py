import re
import copy
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

log = logging.getLogger("executor")


@dataclass
class ActorContext:
    """Authentication and ownership context for one principal."""

    actor_id: str
    role: str = "user"
    auth_token: str = ""
    refresh_token: str = ""
    credentials: Dict[str, Any] = field(default_factory=dict)
    cookies: Dict[str, Any] = field(default_factory=dict)
    owned_resources: Dict[str, set] = field(default_factory=dict)

    def remember_resource(self, resource_type: str, resource_id: Any) -> None:
        self.owned_resources.setdefault(resource_type, set()).add(str(resource_id))

    def to_state_store(self, base: Optional[Dict[str, Any]] = None) -> "StateStore":
        data = dict(base or {})
        data.update(self.credentials)
        data["actor_id"] = self.actor_id
        data["actor_role"] = self.role
        if self.auth_token:
            data["auth_token"] = self.auth_token
        if self.refresh_token:
            data["refresh_token"] = self.refresh_token
        if self.cookies:
            data["auth_cookies"] = copy.deepcopy(self.cookies)
        return StateStore(data)


class MultiActorContextStore:
    """Registry for owner, foreign-user, admin and anonymous principals."""

    def __init__(self):
        self._actors: Dict[str, ActorContext] = {}

    def add(self, actor: ActorContext) -> ActorContext:
        if not actor.actor_id:
            raise ValueError("actor_id must not be empty")
        self._actors[actor.actor_id] = actor
        return actor

    def get(self, actor_id: str) -> Optional[ActorContext]:
        return self._actors.get(actor_id)

    def require(self, actor_id: str) -> ActorContext:
        actor = self.get(actor_id)
        if actor is None:
            raise KeyError(f"Unknown actor: {actor_id}")
        return actor

    def all(self):
        return list(self._actors.values())

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

    def capture_successful_request(self, payload: Dict[str, Any],
                                   inputs_schema: Optional[Dict] = None) -> bool:
        """Persist request values that became valid state after a successful write.

        Some create APIs only return ``status/message``. In that case the
        resource key (for example ``book_title``) exists only in the successful
        request and still has to be available to downstream GET/PUT/DELETE APIs.
        """
        if not isinstance(payload, dict) or not payload:
            return False
        schema = inputs_schema or {}
        captured = False
        for field_name, meta in schema.items():
            meta = meta if isinstance(meta, dict) else {}
            original = meta.get("original", field_name)
            value = payload.get(original, payload.get(field_name))
            if value is None or isinstance(value, (dict, list)):
                continue
            for key in {field_name, original}:
                if key and self.memory.get(key) != value:
                    self.update(key, value)
                    captured = True
        return captured

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

    def extract_from_response(self, response_json: Any, schema: Optional[Dict] = None,
                               api_id: str = "") -> bool:
        """
        Duyệt đệ quy response JSON, so khớp với _HARVEST_PATTERNS,
        tự động ghi vào memory.
        Nếu có schema guide (output fields từ OpenAPI spec) → harvest thêm theo tên field.
        Flatten response trước khi so khớp để xử lý nested wrapper (vd: {"Books": [{...}]}).

        Args:
            api_id: Tên API hiện tại (vd: "create_post"), dùng để tạo contextual key
                    cho trường "id" chung chung → lưu thành "{resource}_id".

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
                    target_key = state_key
                    # Preserve an exact canonical value (e.g. `phone`) when a
                    # second alias such as `mobile_number` appears later.
                    if (state_key in self.memory
                            and resp_key.lower() != state_key.lower()
                            and resp_val != self.memory.get(state_key)):
                        target_key = resp_key
                    if resp_val and resp_val != self.memory.get(target_key):
                        # Strip tiền tố "Bearer "/"Token " nếu server trả về token đã gắn sẵn prefix
                        if state_key == "auth_token" and isinstance(resp_val, str):
                            resp_val = self._TOKEN_PREFIX_RE.sub("", resp_val).strip()
                        self.update(target_key, resp_val)
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
                if self.extract_from_response(resp_val, api_id=api_id):
                    found_new = True
            elif isinstance(resp_val, list):
                for item in resp_val:
                    if isinstance(item, dict):
                        if self.extract_from_response(item, api_id=api_id):
                            found_new = True

        # ── Bước 1d: Contextual ID — trường "id" đơn thuần ──────────────────
        # Response thường trả về "id" (2 ký tự) là primary key của resource vừa tạo.
        # Vấn đề: key "id" quá chung, bị ghi đè liên tục bởi các API khác.
        # Giải pháp: dựa vào api_id (vd: "create_post") → suy ra resource_type = "post"
        #            → lưu thêm "post_id" = value, ngoài "id" = value.
        bare_id = response_json.get("id")
        if bare_id and api_id:
            # Luôn lưu "id" chung
            if bare_id != self.memory.get("id"):
                self.update("id", bare_id)
                found_new = True
            
            # Suy ra resource type từ api_id
            # "create_post" → "post", "addVehicle" → "vehicle", "signup" → "user"
            resource_type = self._infer_resource_type(api_id)
            if resource_type:
                contextual_key = f"{resource_type}_id"
                if bare_id != self.memory.get(contextual_key):
                    self.update(contextual_key, bare_id)
                    log.info(f"\033[96m[State] CONTEXTUAL-ID\033[0m {contextual_key} = {repr(bare_id)[:60]} (from {api_id})")
                    found_new = True

        # ── Bước 2: Schema-guided harvest (dùng output spec làm guide) ──────
        # Flatten toàn bộ response (kể cả nested) để so khớp với spec fields
        flat = self._flatten(response_json)

        if schema:
            schema_items = schema.items() if isinstance(schema, dict) else (
                (field_name, {}) for field_name in schema
            )
            for field_key, field_meta in schema_items:
                orig = field_meta.get("original", field_key) \
                       if isinstance(field_meta, dict) else field_key
                if orig in flat:
                    val = flat[orig]
                    if isinstance(val, (str, int)) and val and val != self.memory.get(orig):
                        self.update(orig, val)
                        log.debug(f"\033[96m[State] SCHEMA-HARVEST\033[0m {orig} = {repr(val)[:60]}")
                        found_new = True

        # ── Bước 3: Conservative fallback ────────────────────────────────────
        # Do not treat generic response metadata (`status`, `message`, ...) as
        # state transitions. Only retain identity/auth fields when the spec did
        # not describe outputs.
        for k, v in flat.items():
            if not isinstance(k, str) or not isinstance(v, (str, int)):
                continue
            if not v or v == self.memory.get(k):
                continue
            # Không được ghi đè các key cấu hình hệ thống (bảo vệ auth_header_prefix, ...)
            if k in self._PROTECTED_KEYS:
                continue
            is_relevant = self._GENERIC_ID_PATTERN.search(k) or any(
                pattern.search(k) for pattern in self._HARVEST_PATTERNS.values()
            )
            if is_relevant and k not in self.memory:
                self.update(k, v)
                found_new = True

        return found_new

    @staticmethod
    def _infer_resource_type(api_id: str) -> str:
        """
        Suy ra resource type từ api_id.
        
        Ví dụ:
          "create_post"     → "post"
          "addVehicle"      → "vehicle"
          "signup"          → "user"
          "createOrder"     → "order"
          "get_post"        → "post"
          "updateProfile"   → "profile"
        """
        # Loại bỏ prefix hành động phổ biến
        cleaned = api_id
        # snake_case: "create_post" → bỏ "create_" → "post"
        action_prefixes = [
            "create_", "add_", "new_", "register_", "post_",
            "get_", "fetch_", "read_", "list_", "find_",
            "update_", "edit_", "modify_", "patch_",
            "delete_", "remove_",
        ]
        for prefix in action_prefixes:
            if cleaned.lower().startswith(prefix):
                cleaned = cleaned[len(prefix):]
                break
        else:
            # camelCase: "createPost" → bỏ "create" → "Post" → "post"
            camel_actions = [
                "create", "add", "new", "register", "post",
                "get", "fetch", "read", "list", "find",
                "update", "edit", "modify", "patch",
                "delete", "remove",
            ]
            for action in camel_actions:
                if cleaned.lower().startswith(action) and len(cleaned) > len(action):
                    rest = cleaned[len(action):]
                    if rest[0].isupper():
                        cleaned = rest
                        break
        
        # Xử lý trường hợp đặc biệt
        special = {
            "signup": "user", "signin": "user", "login": "user",
        }
        if api_id.lower() in special:
            return special[api_id.lower()]
        
        # Normalize kết quả
        resource = re.sub(r'([a-z])([A-Z])', r'\1_\2', cleaned).lower()
        resource = resource.rstrip("s")  # "posts" → "post"
        
        return resource if resource and resource != api_id.lower() else ""

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
