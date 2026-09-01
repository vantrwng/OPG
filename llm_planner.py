"""
llm_planner.py
==============
Điều phối payload generation cho toàn hệ thống.
Chỉ dùng Ollama local (llama3.1:8b) — không phụ thuộc bất kỳ API ngoài nào.

Thứ tự ưu tiên:
  1. Ollama Architect Agent (llama3.1:8b)  — nếu OLLAMA_ENABLED=true và ping OK
  2. Heuristic Fallback                    — luôn sẵn sàng, không cần mạng
"""

import json
import re
import uuid
import logging
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

from ollama_client import OllamaClient, get_ollama_client, OLLAMA_ENABLED
from state_store import StateStore
from response_outcome import evaluate_response
from field_semantics import is_reference_field, value_matches_openapi_type

load_dotenv()
log = logging.getLogger("llm_planner")


class LLMPlanner:
    """
    Quản lý sinh payload cho API Fuzzer.

    Dịch vụ:
      1. classify_unknown_fields()  — phân loại field vào semantic bucket
      2. cluster_identities()       — gom nhóm identity field đồng nghĩa
      3. generate_payload()         — sinh JSON payload cho mỗi request
      4. repair_payload()           — Self-Healing khi server trả về lỗi
    """

    _EMAIL_RE    = re.compile(r"email", re.I)
    _PHONE_RE    = re.compile(r"phone|mobile|contact|^number$", re.I)
    _NAME_RE     = re.compile(r"^(name|full_?name|display_?name|user_?name)$", re.I)
    _PASSWORD_RE = re.compile(r"pass(word)?|passwd", re.I)

    def __init__(self):
        # ── Ollama Architect Agent (llama3.1:8b) ──────────────────────────────
        self._ollama: Optional[OllamaClient] = None
        if OLLAMA_ENABLED:
            client = get_ollama_client()
            if client.ping():
                self._ollama = client
                log.info("[LLMPlanner] ✅ Ollama connected — Architect Agent (llama3.1:8b) ready")
            else:
                log.warning("[LLMPlanner] ⚠ Ollama không phản hồi — chạy heuristic only")
        else:
            log.info("[LLMPlanner] OLLAMA_ENABLED=false — heuristic only")

        self.max_retries = 2

        # Cache để tránh gọi LLM lại với cùng prompt
        self._llm_cache: Dict[str, str]        = {}   # field → semantic category
        self._identity_cluster_map: Dict[str, int] = {}
        self._payload_cache: Dict[str, Dict]   = {}   # prompt_hash → payload
        self._schema_cache: Dict[str, Any]     = {}   # api_id → schema (invalidate khi 400)

    # ── 1. Semantic Classification ────────────────────────────────────────────

    def classify_unknown_fields(self, unknown_fields: List[str]) -> Dict[str, str]:
        """
        Phân loại các field 'unknown' vào semantic bucket bằng Ollama.
        Fallback: trả về dict rỗng → graph_builder dùng rule-based.
        """
        if not unknown_fields or not self._ollama:
            return {}

        fields_list = "\n".join([f"- {f}" for f in unknown_fields])
        prompt = f"""You are an API security expert analyzing REST API field dependencies.

Classify each field name below into ONE of these semantic categories:
- "identity": Unique identifiers for resources (e.g. user_id, vin, order_no, patient_ref, pincode as location id)
- "auth/workflow": Authentication tokens, session keys, workflow state codes
- "finance": Monetary values, prices, balances, fees
- "unknown": Cannot be determined

Respond ONLY with a valid JSON object. Keys are field names, values are the category string.
Example: {{"vin": "identity", "conversion_param": "unknown", "pincode": "identity"}}

Fields to classify:
{fields_list}"""

        try:
            result = self._ollama.architect(prompt=prompt, temperature=0.0)
            if not result or not isinstance(result, dict):
                return {}

            # Lọc chỉ giữ category hợp lệ
            valid_cats = {"identity", "auth/workflow", "finance", "unknown"}
            filtered = {k: v for k, v in result.items()
                        if isinstance(v, str) and v in valid_cats}

            for field, category in filtered.items():
                if category != "unknown":
                    self._llm_cache[field] = category
                    log.info(f"  [Classify] '{field}' → {category}")

            return filtered
        except Exception as e:
            log.error(f"[classify_unknown_fields] Error: {e}")
            return {}

    def get_semantic_cache(self, field: str) -> Optional[str]:
        return self._llm_cache.get(field)

    # ── 2. Identity Clustering ────────────────────────────────────────────────

    def cluster_identities(self, identity_fields: List[str]) -> Dict[str, int]:
        """
        Gom nhóm các Identity field đồng nghĩa bằng Ollama.
        Fallback: mỗi field là một cluster riêng.
        """
        if not identity_fields:
            return {}

        if not self._ollama:
            # Heuristic fallback: mỗi field tự thành 1 cluster
            return {f: i for i, f in enumerate(identity_fields)}

        fields_repr = ", ".join([f'"{f}"' for f in sorted(identity_fields)])
        prompt = f"""You are an API security expert.

Group the following API field names that are synonyms or refer to the same real-world entity into sub-arrays.
Field names: [{fields_repr}]

Rules:
- Group fields that clearly identify the SAME entity (e.g. "user id", "userid", "account id" → same group).
- Domain-specific IDs from different entities must stay separate (e.g. "vehicle id" ≠ "order id").
- Each field must appear in exactly one group.
- Respond ONLY with a valid JSON object: {{"clusters": [["field1", "field2"], ["field3"]]}}"""

        try:
            result = self._ollama.architect(prompt=prompt, temperature=0.0)
            if not result or not isinstance(result.get("clusters"), list):
                log.warning("[cluster_identities] Invalid response — fallback to 1-field clusters")
                return {f: i for i, f in enumerate(identity_fields)}

            clusters = result["clusters"]
            for cluster_id, group in enumerate(clusters):
                if isinstance(group, list):
                    for field in group:
                        self._identity_cluster_map[str(field)] = cluster_id

            log.info(f"  [Cluster] {len(identity_fields)} fields → {len(clusters)} clusters")
            for cid, grp in enumerate(clusters):
                log.info(f"    Cluster #{cid}: {grp}")

            return self._identity_cluster_map
        except Exception as e:
            log.error(f"[cluster_identities] Error: {e}")
            return {f: i for i, f in enumerate(identity_fields)}

    def get_cluster_map(self) -> Dict[str, int]:
        return self._identity_cluster_map

    # ── 3. Payload Generation ─────────────────────────────────────────────────

    @staticmethod
    def _norm(name: str) -> str:
        return re.sub(r'[_\-\.\s]', '', str(name)).lower()

    def generate_payload(
        self,
        api_node: Dict,
        state: StateStore,
        edge_deps: Optional[list] = None,
    ) -> Tuple[Dict[str, Any], str]:
        """
        Sinh payload cho một API request.

        Returns:
            (payload_dict, source_label)
            source_label: "OLLAMA_ARCHITECT" | "HEURISTIC" | "NONE"
        """
        method = api_node.get("method", "GET").upper()
        if method in ("GET", "DELETE") and not api_node.get("inputs"):
            return {}, "NONE"

        payload = None
        source  = "HEURISTIC"

        # ── Ưu tiên 1: Ollama Architect ──────────────────────────────────────
        if self._ollama:
            payload = self._ollama_generate(api_node, state, edge_deps=edge_deps)
            if payload is not None:
                source = "OLLAMA_ARCHITECT"

        # ── Ưu tiên 2: Heuristic ─────────────────────────────────────────────
        if payload is None:
            payload = self._heuristic_generate(api_node, state, edge_deps=edge_deps)

        payload = self._apply_context_bindings(payload or {}, api_node, state, edge_deps)

        # Post-process: randomize volatile fields (email, phone, name, password)
        if payload:
            payload = self._randomize_volatile_fields(payload, api_node, state)

        log.info(
            f"  [{source}] {api_node.get('id')} → "
            f"{json.dumps(payload, ensure_ascii=False)[:120]}"
        )
        return payload, source

    def _apply_context_bindings(
        self,
        payload: Dict[str, Any],
        api_node: Dict,
        state: StateStore,
        edge_deps: Optional[list] = None,
    ) -> Dict[str, Any]:
        """Deterministically bind downstream inputs to producer/state values."""
        out = dict(payload)
        dependency_values: Dict[str, Any] = {}
        for dep in edge_deps or []:
            producer = dep.get("producer_field", "")
            consumer = dep.get("consumer_field", "")
            producer_norm = self._norm(producer)
            for state_key, state_value in state.memory.items():
                if self._norm(state_key) == producer_norm:
                    dependency_values[self._norm(consumer)] = state_value
                    break

        method = api_node.get("method", "GET").upper()
        endpoint_text = " ".join((
            str(api_node.get("id", "")), str(api_node.get("path", ""))
        ))
        is_login = bool(re.search(
            r"login|log[_-]?in|signin|sign[_-]?in|authenticate|issue[_-]?token",
            endpoint_text, re.I,
        ))

        for field_name, meta in (api_node.get("inputs", {}) or {}).items():
            meta = meta if isinstance(meta, dict) else {}
            original = meta.get("original", field_name)
            location = str(meta.get("in", "body")).lower()
            field_norm = self._norm(field_name)
            original_norm = self._norm(original)
            bound = dependency_values.get(original_norm, dependency_values.get(field_norm))

            # A reference already produced inside this actor/beam is stronger
            # evidence than an LLM guess or a fuzzy ODG edge. This also covers
            # optional POST-body references omitted from OpenAPI `required`.
            if is_reference_field(field_name, meta):
                for state_key, state_value in state.memory.items():
                    if self._norm(state_key) not in (field_norm, original_norm):
                        continue
                    if value_matches_openapi_type(state_value, meta):
                        bound = state_value
                        break

            # Login credentials are an atomic actor snapshot. Never combine a
            # frozen username with a password overwritten by another signup
            # branch in the mutable workflow state.
            if bound is None and is_login and location == "body":
                bound = state.get_actor_credential(original)
                if bound is None:
                    bound = state.get_actor_credential(field_name)

            # During valid workflow generation, authenticated identity path
            # parameters must match the token principal. Attack variants bypass
            # this planner by using an explicit payload/path override.
            principal_value = None
            if location == "path" and state.has("auth_token"):
                principal_value = state.get_actor_identity(original)
                if principal_value is None:
                    principal_value = state.get_actor_identity(field_name)
            if principal_value is not None:
                bound = principal_value

            # Non-reference POST body values are generated fresh unless an ODG
            # dependency explicitly binds them. Other locations/methods consume
            # existing state deterministically.
            may_consume_state = method != "POST" or location != "body"
            if bound is None and may_consume_state:
                for state_key, state_value in state.memory.items():
                    state_norm = self._norm(state_key)
                    if state_norm in (field_norm, original_norm):
                        bound = state_value
                        break

            if bound is not None:
                target_key = original if original in out or field_name not in out else field_name
                out[target_key] = bound
        return out

    def _build_prompt(
        self,
        api_node: Dict,
        state: StateStore,
        edge_deps: Optional[list] = None,
    ) -> str:
        """Xây dựng prompt chung cho cả generate và repair."""
        inputs_schema = api_node.get("inputs", {})
        path          = api_node.get("path", "")
        method        = api_node.get("method", "")

        # Schema block
        field_lines = []
        for field_name, meta in inputs_schema.items():
            if isinstance(meta, dict):
                ftype = meta.get("type", "string")
                ffmt  = meta.get("format", "")
                forig = meta.get("original", field_name)
                constraints = []
                if meta.get("enum"):
                    constraints.append(f"allowed: {meta['enum']}")
                if meta.get("default") is not None:
                    constraints.append(f"default: {meta['default']!r}")
                constraint_text = f", {', '.join(constraints)}" if constraints else ""
                field_lines.append(
                    f"  - {forig} (type: {ftype}, format: {ffmt}{constraint_text})"
                )
            else:
                field_lines.append(f"  - {field_name}")
        fields_block = "\n".join(field_lines) if field_lines else "  (no explicit schema)"

        # Detect endpoint type
        combined  = path + " " + api_node.get("id", "").lower()
        is_create = bool(re.search(r"signup|register|create|add", combined))
        is_login  = bool(re.search(r"login|signin|sign_in|authenticate", combined))

        # Context block
        SKIP_KEYS = {"auth_token", "token_type", "user_role"}

        context_lines = [
            f'  - {k}: "{v}"'
            for k, v in state.memory.items()
            if k not in SKIP_KEYS
        ]
        context_block = "\n".join(context_lines) if context_lines else "  (empty — no prior state)"

        # Login hint
        login_hint = ""
        if is_login and state.has("email") and state.has("password"):
            login_hint = f"""
⚠️  IMPORTANT — This is a LOGIN endpoint.
The user already REGISTERED with:
  - email: "{state.get('email')}"
  - password: "{state.get('password')}"
You MUST use EXACTLY these values.
"""

        # Dependency block
        dep_lines = []
        if edge_deps:
            for dep in edge_deps:
                prod      = dep.get("producer_field", "")
                cons      = dep.get("consumer_field", "")
                prod_norm = self._norm(prod)
                for sk, sv in state.memory.items():
                    if self._norm(sk) == prod_norm:
                        dep_lines.append(f"  - MUST USE state['{sk}'] for field '{cons}'")
                        break
        dep_block = "\n".join(dep_lines) if dep_lines else "  (no explicit edge dependencies)"

        return f"""You are an expert API Fuzzer. Generate a valid JSON payload for this HTTP request.
Endpoint: {method} {path}
{login_hint}
1. Schema Requirements (Fields to include):
{fields_block}

2. Available Context (Prior API outputs — USE THESE VALUES when relevant):
{context_block}

3. Strict Dependencies (ODG mappings - YOU MUST OBEY THESE):
{dep_block}

RULES:
- Respond ONLY with a valid JSON object. No markdown, no explanation.
- Map fields exactly as required by the Strict Dependencies.
- If a field value is available in the Context, YOU MUST use that exact value.
- For email fields on NON-LOGIN endpoints: generate a UNIQUE, RANDOM email like fuzz_{{random_hex}}@test.com.
- For password fields on NON-LOGIN endpoints: use a strong password with uppercase, number, symbol.
- For other missing fields, generate realistic synthetic data.
"""

    def _ollama_generate(
        self,
        api_node: Dict,
        state: StateStore,
        edge_deps: Optional[list] = None,
    ) -> Optional[Dict]:
        """Gọi Ollama Architect Agent để sinh payload."""
        prompt      = self._build_prompt(api_node, state, edge_deps)
        prompt_hash = hashlib.md5(prompt.encode("utf-8")).hexdigest()

        if prompt_hash in self._payload_cache:
            log.info(f"  [Ollama] CACHE HIT — {api_node.get('id')}")
            return self._payload_cache[prompt_hash].copy()

        try:
            result = self._ollama.architect(
                prompt=prompt,
                system=(
                    "You are an expert API Fuzzer. "
                    "Generate valid JSON payloads for REST API testing. "
                    "Respond ONLY with a valid JSON object."
                ),
                temperature=0.4,
            )
            if result and isinstance(result, dict):
                self._payload_cache[prompt_hash] = result
                log.info(
                    f"  [Ollama Architect] Generated {len(result)} fields "
                    f"for {api_node.get('id')}"
                )
                return result.copy()

            log.warning(f"  [Ollama Architect] Non-dict response for {api_node.get('id')}")
            return None
        except Exception as e:
            log.error(f"  [Ollama Architect] Error: {e}")
            return None

    # ── 4. Self-Healing (repair_payload) ─────────────────────────────────────

    def repair_payload(
        self,
        api_node: Dict,
        state: StateStore,
        bad_payload: Dict,
        error_response: str,
        edge_deps: Optional[list] = None,
        knowledge_memory=None,
    ) -> Optional[Dict]:
        """
        Gửi payload lỗi + server error + ngữ cảnh state/response cho Ollama để fix tự động (Self-Healing).
        
        Cải tiến: Truyền thêm:
          - Toàn bộ StateStore hiện tại (giá trị thực đang có)
          - Response thành công gần nhất của API (nếu có trong KnowledgeMemory)
        Giúp AI hiểu rõ ngữ cảnh để sửa payload chính xác hơn.
        
        Fallback: trả về None → RequestExecutor bỏ qua repair.
        """
        if not self._ollama:
            log.warning("[Repair] Ollama unavailable — skipping self-healing")
            return None

        base_prompt  = self._build_prompt(api_node, state, edge_deps)
        
        # ── Bổ sung: Liệt kê toàn bộ StateStore hiện tại ─────────────────────
        state_lines = []
        for k, v in state.memory.items():
            if k in ("auth_token",):
                state_lines.append(f'  - {k}: "(present, {len(str(v))} chars)"')
            else:
                state_lines.append(f'  - {k}: "{v}"')
        state_block = "\n".join(state_lines) if state_lines else "  (empty)"
        
        # ── Bổ sung: Response thành công gần nhất của API này ─────────────────
        recent_success_block = ""
        api_id = api_node.get("id", "")
        if knowledge_memory:
            endpoint_data = knowledge_memory.endpoint_stats.get(api_id, {})
            all_requests = endpoint_data.get("all_requests", [])
            # Tìm request thành công gần nhất (status 200/201/202)
            for req in reversed(all_requests):
                req_status = str(req.get("status", ""))
                req_successful = req.get("successful")
                if req_successful is None:
                    req_successful = evaluate_response(
                        req_status,
                        response_text=req.get("response_text", ""),
                    ).successful
                if req_successful:
                    resp_text = req.get("response_text", "")[:500]
                    req_payload = json.dumps(req.get("request_payload", {}), ensure_ascii=False)[:300]
                    recent_success_block = (
                        f"\n\nRECENT SUCCESSFUL REQUEST (for reference — this payload WORKED before):\n"
                        f"  Payload that worked: {req_payload}\n"
                        f"  Server response: {resp_text}\n"
                    )
                    break

        # Loại bỏ truncation chặt: giới hạn ở 2000 ký tự để có tối đa thông tin nhưng không văng token limit
        error_resp_str = error_response[:2000] if error_response else ""

        repair_prompt = (
            base_prompt
            + f"\n\nCURRENT STATE STORE (all available values right now):\n{state_block}\n"
            + recent_success_block
            + "\n\nCRITICAL ERROR — The previous payload caused an HTTP Error!\n"
            f"Previous Payload:\n{json.dumps(bad_payload, indent=2, ensure_ascii=False)}\n"
            f"Server Error (RAW RESPONSE):\n{error_resp_str}\n\n"
            "YOUR TASK:\n"
            "1. Read the Server Error carefully.\n"
            "2. Identify explicit constraints (e.g., max length, minimum value, required format, duplicate record).\n"
            "3. Determine which fields in the Previous Payload caused the error.\n"
            "4. Provide the SPECIFIC changes needed to fix the payload.\n"
            "   - Only modify fields that are causing the error.\n"
            "   - If the error is about a duplicate/conflict, generate a COMPLETELY NEW, random value for that field.\n"
            "   - If the error is about validation (size, pattern), adjust the value to satisfy the constraint.\n"
            "\n"
            "Respond ONLY with a JSON object in this exact format:\n"
            "{\n"
            '  "action": "MODIFY", // or "NO_CHANGE" if you cannot determine how to fix it\n'
            '  "error_type": "VALIDATION", // e.g., VALIDATION, CONFLICT, AUTHENTICATION, SERVER_ERROR, UNKNOWN\n'
            '  "evidence": ["Quote or summarize the exact constraint from the Server Error"],\n'
            '  "changes": {\n'
            '    "field_name_to_change": "new_valid_value"\n'
            '  },\n'
            '  "reason": "Explain why this change fixes the error."\n'
            "}"
        )

        log.warning(
            f"\033[93m[Self-Healing]\033[0m Ollama analyzing error for {api_node.get('id')}"
        )

        try:
            result = self._ollama.architect(
                prompt=repair_prompt,
                system=(
                    "You are an expert API Fuzzer analyzing server responses. "
                    "Extract constraints directly from the raw response. "
                    "Respond ONLY with the requested structured JSON object. Do not include full payloads, only the changes."
                ),
                temperature=0.1, # Giảm temp để phân tích chính xác
            )
            
            if not result or not isinstance(result, dict):
                log.error("[Self-Healing] Invalid JSON format from LLM.")
                return None
                
            # Backward compatibility for older/local models that return the
            # changed fields directly instead of the structured envelope.
            direct_changes = {
                k: v for k, v in result.items()
                if k in bad_payload and k not in {"action", "changes"}
            }
            if "action" not in result and "changes" not in result and direct_changes:
                action = "MODIFY"
                changes = direct_changes
            else:
                action = result.get("action", "NO_CHANGE")
                changes = result.get("changes", {})
            log.info(f"\033[94m[LLM DECISION]\033[0m Action: {action}, ErrorType: {result.get('error_type')}, Reason: {result.get('reason')}")
            
            if action == "NO_CHANGE":
                return None
                
            if not changes or not isinstance(changes, dict):
                log.info("[Self-Healing] No valid changes provided by LLM.")
                return None
                
            log.info(f"\033[94m[PAYLOAD CHANGES]\033[0m {list(changes.keys())}")
            
            # Merge changes vào payload cũ
            repaired_payload = bad_payload.copy()
            for k, v in changes.items():
                # Xử lý nested dictionary một cách cơ bản
                if "." in k:
                    parts = k.split(".")
                    curr = repaired_payload
                    for part in parts[:-1]:
                        if part not in curr or not isinstance(curr[part], dict):
                            curr[part] = {}
                        curr = curr[part]
                    curr[parts[-1]] = v
                else:
                    repaired_payload[k] = v
                    
            return repaired_payload

        except Exception as e:
            log.error(f"[Self-Healing] Error during analysis: {e}")
            return None

    # ── Heuristic Fallback ────────────────────────────────────────────────────

    def _heuristic_generate(
        self,
        api_node: Dict,
        state: StateStore,
        edge_deps: Optional[list] = None,
    ) -> Dict:
        """
        Sinh payload thuần rule-based không cần LLM.
        Ưu tiên: edge_deps > StateStore match > default fuzz value.
        """
        dep_map: Dict[str, Any] = {}
        if edge_deps:
            for dep in edge_deps:
                prod      = dep.get("producer_field", "")
                cons      = dep.get("consumer_field", "")
                prod_norm = self._norm(prod)
                for sk, sv in state.memory.items():
                    if self._norm(sk) == prod_norm:
                        dep_map[self._norm(cons)] = sv
                        break

        payload = {}
        for field_name, meta in api_node.get("inputs", {}).items():
            original  = meta.get("original", field_name) if isinstance(meta, dict) else field_name
            ftype     = meta.get("type", "string")       if isinstance(meta, dict) else "string"
            enum      = list(meta.get("enum", []) or []) if isinstance(meta, dict) else []
            default   = meta.get("default")              if isinstance(meta, dict) else None
            orig_norm = self._norm(original)
            fld_norm  = self._norm(field_name)

            if isinstance(meta, dict) and meta.get("is_file"):
                payload[original] = {"$artifact": "builtin_valid_fixture"}
            # 1. Edge dependency
            elif orig_norm in dep_map:
                payload[original] = dep_map[orig_norm]
            elif fld_norm in dep_map:
                payload[original] = dep_map[fld_norm]
            elif default is not None:
                payload[original] = default
            elif enum:
                payload[original] = enum[0]
            else:
                # 2. StateStore match (không tự động kéo email cũ)
                matched_val = None
                if orig_norm != "email" and fld_norm != "email":
                    for sk, sv in state.memory.items():
                        sk_norm = self._norm(sk)
                        if sk_norm == orig_norm or sk_norm == fld_norm:
                            matched_val = sv
                            break

                payload[original] = matched_val if matched_val is not None \
                    else self._default_fuzz_value(ftype, original)

        return payload

    # ── Post-processing ───────────────────────────────────────────────────────

    @staticmethod
    def _randomize_volatile_fields(
        payload: Dict,
        api_node: Dict,
        state: StateStore,
    ) -> Dict:
        """
        Post-process payload: xử lý email/phone/name/password theo API type.
          CREATE  → luôn sinh mới (tránh duplicate)
          AUTH    → dùng giá trị từ StateStore
          OTHER   → ưu tiên StateStore, fallback sinh mới
        """
        hex6     = uuid.uuid4().hex[:6]
        hex4     = uuid.uuid4().hex[:4]
        rand_pass = (
            uuid.uuid4().hex[:4].upper()
            + uuid.uuid4().hex[:4]
            + f"@{uuid.uuid4().int % 999 + 1}!"
        )

        combined = api_node.get("path", "").lower() + " " + api_node.get("id", "").lower()
        if re.search(r"signup|register|create|add", combined):
            api_type = "CREATE"
        elif re.search(r"login|verify|forgot|reset|auth|signin", combined):
            api_type = "AUTH"
        else:
            api_type = "OTHER"

        out: Dict[str, Any] = {}
        for k, v in payload.items():
            # Đệ quy vào nested dict/list
            if isinstance(v, dict):
                out[k] = LLMPlanner._randomize_volatile_fields(v, api_node, state)
                continue
            if isinstance(v, list):
                out[k] = [
                    LLMPlanner._randomize_volatile_fields(item, api_node, state)
                    if isinstance(item, dict) else item
                    for item in v
                ]
                continue

            is_email = LLMPlanner._EMAIL_RE.search(k)
            is_phone = LLMPlanner._PHONE_RE.search(k)
            is_name  = LLMPlanner._NAME_RE.search(k)
            is_pass  = LLMPlanner._PASSWORD_RE.search(k)

            if not (is_email or is_phone or is_name or is_pass):
                out[k] = v
                continue

            input_meta = None
            for field_name, meta in (api_node.get("inputs", {}) or {}).items():
                meta = meta if isinstance(meta, dict) else {}
                if k in (field_name, meta.get("original", field_name)):
                    input_meta = meta
                    break
            if input_meta and input_meta.get("in") == "path" and state.has("auth_token"):
                principal_value = state.get_actor_identity(k)
                if principal_value is not None:
                    out[k] = principal_value
                    continue

            # CREATE must establish a fresh identity. AUTH and OTHER requests
            # reuse the actor's stored credentials to preserve session flow.
            matched = None
            if api_type != "CREATE":
                if api_type == "AUTH" and (is_email or is_name or is_pass or is_phone):
                    matched = state.get_actor_credential(k)
                if matched is None and api_type == "AUTH" and (is_email or is_name):
                    matched = state.get_actor_identity(k)
                if matched is None:
                    if is_email:  matched = state.get("email")
                    elif is_pass:  matched = state.get("password")
                    elif is_phone: matched = state.get("number") or state.get("phone") or state.get("mobile")
                    elif is_name:  matched = state.get("name") or state.get("username")

            if matched is not None:
                out[k] = matched
            else:
                out[k] = (
                    f"fuzz_{hex6}@test.com" if is_email else
                    f"09{uuid.uuid4().int % 100_000_000:08d}" if is_phone else
                    f"Fuzzer {hex4.upper()}" if is_name else
                    rand_pass
                )

        return out

    @staticmethod
    def _default_fuzz_value(ftype: str, field_name: str) -> Any:
        if ftype == "integer": return 1
        if ftype == "number":  return 0.01
        if ftype == "boolean": return True
        if re.search(r"email",          field_name, re.I): return f"fuzz_{uuid.uuid4().hex[:6]}@test.com"
        if re.search(r"phone|mobile|number", field_name, re.I): return "+84900000000"
        if re.search(r"password|pass",  field_name, re.I): return "Fuzz@12345!"
        return "fuzz_test_value"
