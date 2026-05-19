import os
import json
import re
import time
import uuid
import logging
import hashlib
from typing import Any, Dict, Optional, List, Tuple
from openai import OpenAI, RateLimitError, APIError
from dotenv import load_dotenv
from pydantic import ValidationError
from state_store import StateStore
from llm_schemas import (
    SemanticClassificationResponse,
    IdentityClusterResponse,
    PayloadResponse,
    LLMRepairResponse,
    validate_json_response
)

load_dotenv()
log = logging.getLogger("executor")

class LLMPlanner:
    """
    Quản lý giao tiếp với OpenAI/GitHub Models.
    Cung cấp các dịch vụ: 
      1. Phân loại trường (Semantic Classification)
      2. Gom nhóm thực thể (Identity Clustering)
      3. Sinh payload JSON thông minh (Payload Generation)
    """
    _EMAIL_RE    = re.compile(r"email", re.I)
    _PHONE_RE    = re.compile(r"phone|mobile|contact|^number$", re.I)
    _NAME_RE     = re.compile(r"^(name|full_?name|display_?name|user_?name)$", re.I)
    _PASSWORD_RE = re.compile(r"pass(word)?|passwd", re.I)

    def __init__(self):
        openai_key     = os.getenv("OPENAI_API_KEY", "")
        github_token   = os.getenv("GITHUB_TOKEN", "")

        if openai_key:
            # Dùng OpenAI-compatible API
            self.endpoint = "https://codex.xirothedev.io.vn/v1"
            self.model    = "gpt-5.5"
            api_key       = openai_key
            log.info("[LLMPlanner] Using Custom OpenAI API — model: gpt-5.5")
        elif github_token:
            # Fallback: GitHub Models
            self.endpoint = "https://models.github.ai/inference"
            self.model    = "gpt-4o-mini"
            api_key       = github_token
            log.info("[LLMPlanner] Using GitHub Models — model: gpt-4o-mini")
        else:
            self.endpoint = ""
            self.model    = ""
            api_key       = ""
            log.warning("[LLMPlanner] No API key found — heuristic fallback only.")

        self.max_retries = 2
        self._client = OpenAI(
            base_url=self.endpoint,
            api_key=api_key,
        ) if api_key else None

        self._llm_cache = {}
        self._identity_cluster_map = {}
        self._payload_cache = {}
        self._schema_cache = {}   # schema cache cho mỗi api_id, dùng để invalidate khi cần

    def classify_unknown_fields(self, unknown_fields: List[str]) -> Dict[str, str]:
        """Gọi LLM để phân loại các field 'unknown'."""
        if not unknown_fields or not self._client:
            return {}
        try:
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

            response = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.0
            )
            raw_json = response.choices[0].message.content
            
            # ✅ VALIDATE response với Pydantic
            try:
                validated = validate_json_response(raw_json, SemanticClassificationResponse)
                log.info(f"  [LLM] {self.model} OK - validated {len(validated)} fields")
            except ValueError as validation_err:
                log.error(f"  [LLM] JSON validation failed: {validation_err}")
                return {}  # Fallback nếu invalid
            
            result = validated
            
            # Cập nhật cache
            for field, category in result.items():
                if category in ('identity', 'auth/workflow', 'finance'):
                    self._llm_cache[field] = category
                    log.info(f"  [LLM] '{field}' \u2192 {category}")
            return result
        except Exception as e:
            if '429' in str(e) or 'quota' in str(e).lower() or 'rate' in str(e).lower():
                log.warning("  [LLM] Rate limit — bỏ qua LLM layer, tiếp tục với rule-based.")
            else:
                log.error(f"  [LLM] Warning: {e}")
            return {}

    def get_semantic_cache(self, field: str) -> Optional[str]:
        return self._llm_cache.get(field)

    def cluster_identities(self, identity_fields: List[str]) -> Dict[str, int]:
        """Gom nhóm các Identity field đồng nghĩa bằng LLM."""
        if not identity_fields or not self._client:
            log.warning("  [LLM Cluster] Không có token hoặc không có field nào để cluster.")
            return {}
        try:
            fields_repr = ", ".join([f'"{f}"' for f in sorted(identity_fields)])
            prompt = f"""You are an API security expert.

Group the following API field names that are synonyms or refer to the same real-world entity into sub-arrays.
Field names: [{fields_repr}]

Rules:
- Group fields that clearly identify the SAME entity (e.g. \"user id\", \"userid\", \"account id\" → same group).
- Domain-specific IDs from different entities must stay separate (e.g. \"vehicle id\" ≠ \"order id\").
- Each field must appear in exactly one group.
- Respond ONLY with a valid JSON object: {{"clusters": [["field1", "field2"], ["field3"]]}}"""

            response = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.0
            )
            raw_json = response.choices[0].message.content
            
            # ✅ VALIDATE response với Pydantic
            try:
                validated = validate_json_response(raw_json, IdentityClusterResponse)
                clusters = validated['clusters']
                log.info(f"  [LLM Cluster] OK - validated {len(clusters)} clusters")
            except ValueError as validation_err:
                log.error(f"  [LLM Cluster] JSON validation failed: {validation_err}")
                return {}  # Fallback nếu invalid
            except json.JSONDecodeError as json_err:
                log.error(f"  [LLM Cluster] JSON decode failed: {json_err}")
                return {}

            for cluster_id, group in enumerate(clusters):
                if isinstance(group, list):
                    for field in group:
                        self._identity_cluster_map[str(field)] = cluster_id

            log.info(f"  [LLM Cluster] OK: {len(identity_fields)} fields → {len(clusters)} clusters.")
            for cid, group in enumerate(clusters):
                log.info(f"    Cluster #{cid}: {group}")
            return self._identity_cluster_map
        except Exception as e:
            if '429' in str(e) or 'rate' in str(e).lower():
                log.warning("  [LLM Cluster] Rate limit — bỏ qua Identity Clustering.")
            else:
                log.error(f"  [LLM Cluster] Warning: {e}")
            return {}

    def get_cluster_map(self) -> Dict[str, int]:
        return self._identity_cluster_map

    # ── Payload Generation (Gom từ LLMPayloadGenerator cũ) ──
    @staticmethod
    def _norm(name: str) -> str:
        return re.sub(r'[_\-\.\s]', '', str(name)).lower()

    def generate_payload(self, api_node: Dict, state: StateStore, edge_deps: Optional[list] = None) -> Tuple[Dict[str, Any], str]:
        method = api_node.get("method", "GET").upper()
        if method in ("GET", "DELETE"):
            return {}, "NONE"

        # Tính dep_map trước để truyền sang _randomize_volatile_fields
        # Mục đích: bảo vệ các field đã được resolve từ ODG edge dep khỏi bị randomize mù
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

        source = "LLM"
        payload = self._llm_generate(api_node, state, edge_deps=edge_deps)
        if payload is None:
            source = "HEURISTIC"
            payload = self._heuristic_generate(api_node, state, edge_deps=edge_deps)
            
        # Đảm bảo rule cuối cùng được áp dụng cho mọi source
        if payload:
            payload = self._randomize_volatile_fields(payload, api_node, state, dep_map=dep_map)
            
        log.info(f"  [{source} Payload] {api_node.get('id')} → {json.dumps(payload, ensure_ascii=False)}")
        return payload, source

    def _build_prompt(self, api_node: Dict, state: StateStore, edge_deps: Optional[list] = None) -> str:
        inputs_schema = api_node.get("inputs", {})
        path          = api_node.get("path", "")
        method        = api_node.get("method", "")

        field_lines = []
        for field_name, meta in inputs_schema.items():
            if isinstance(meta, dict):
                ftype = meta.get("type", "string")
                ffmt  = meta.get("format", "")
                forig = meta.get("original", field_name)
                field_lines.append(f"  - {forig} (type: {ftype}, format: {ffmt})")
            else:
                field_lines.append(f"  - {field_name}")
        fields_block = "\n".join(field_lines) if field_lines else "  (no explicit schema)"

        combined = path + " " + api_node.get("id", "").lower()
        is_create = bool(re.search(r"signup|register|create|add", combined))

        SKIP_KEYS = {"auth_token", "token_type", "user_role"}
        if is_create:
            # Ép sinh mới hoàn toàn
            SKIP_KEYS.update({"email", "password", "name", "number", "phone", "mobile"})

        context_lines = []
        for k, v in state.memory.items():
            if k in SKIP_KEYS:
                continue
            context_lines.append(f"  - {k}: \"{v}\"")
        context_block = "\n".join(context_lines) if context_lines else "  (empty — no prior state)"

        dep_lines = []
        if edge_deps:
            for dep in edge_deps:
                prod = dep.get("producer_field", "")
                cons = dep.get("consumer_field", "")
                prod_norm = self._norm(prod)
                for sk, sv in state.memory.items():
                    if self._norm(sk) == prod_norm:
                        dep_lines.append(f"  - MUST USE state['{sk}'] for field '{cons}'")
                        break
        dep_block = "\n".join(dep_lines) if dep_lines else "  (no explicit edge dependencies)"

        prompt = f"""You are an expert API Fuzzer. Generate a valid JSON payload for this HTTP request.
Endpoint: {method} {path}

1. Schema Requirements (Fields to include):
{fields_block}

2. Available Context (Prior API outputs):
{context_block}

3. Strict Dependencies (ODG mappings - YOU MUST OBEY THESE):
{dep_block}

RULES:
- Respond ONLY with a valid JSON object. No markdown tags, no explanations.
- Map fields exactly as required by the Strict Dependencies.
- For other fields, if a matching context variable exists, use its value.
- For email fields: generate a UNIQUE, RANDOM email like fuzz_{{random_hex}}@test.com. NEVER use john.doe@example.com or any example.com address.
- For password fields: use a valid password with uppercase, number, and symbol.
- For other missing fields, generate realistic synthetic data.
"""
        return prompt

    def _llm_generate(self, api_node: Dict, state: StateStore, edge_deps: Optional[list] = None) -> Optional[Dict]:
        if not self._client:
            return None
        prompt = self._build_prompt(api_node, state, edge_deps)
        prompt_hash = hashlib.md5(prompt.encode('utf-8')).hexdigest()
        if prompt_hash in self._payload_cache:
            log.info(f"  [LLM Payload] CACHE HIT for {api_node['id']}")
            cached = self._payload_cache[prompt_hash].copy()
            return cached
            
        for attempt in range(self.max_retries):
            try:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    response_format={"type": "json_object"},
                    temperature=0.7,
                    max_tokens=512,
                )
                raw = response.choices[0].message.content
                
                # ✅ VALIDATE response với Pydantic
                try:
                    validated = validate_json_response(raw, PayloadResponse)
                    parsed = validated
                    self._payload_cache[prompt_hash] = parsed
                    log.info(f"[LLM Payload] Generated {len(parsed)} fields")
                    return parsed.copy()
                except ValueError as validation_err:
                    log.error(f"[LLM] Payload validation failed: {validation_err}")
                    return None  # Fallback to heuristic
            except RateLimitError:
                log.warning(f"[LLM] Rate limit hit — waiting 5s (attempt {attempt})")
                time.sleep(5)
            except json.JSONDecodeError as e:
                log.error(f"[LLM] JSONDecodeError: {e}")
                return None
            except APIError as e:
                log.error(f"[LLM] APIError: {e}")
                return None
            except Exception as e:
                log.error(f"[LLM] Unexpected error: {e}")
                return None
        return None

    def repair_payload(self, api_node: Dict, state: StateStore, bad_payload: Dict, error_response: str, edge_deps: Optional[list] = None) -> Optional[Dict]:
        """Gửi payload bị lỗi và server response cho LLM để fix tự động."""
        if not self._client:
            return None
            
        base_prompt = self._build_prompt(api_node, state, edge_deps)
        
        repair_prompt = f"{base_prompt}\n\n" + f"""CRITICAL ERROR:
The previous payload generated for this endpoint caused an HTTP Error!
Previous Payload:
{json.dumps(bad_payload, indent=2, ensure_ascii=False)}

Server Error Response:
{error_response}

YOUR TASK:
Analyze the error response and FIX the payload to satisfy the server's requirements.
CRITICAL RULE FOR REPAIR: If the error indicates a duplicate value (e.g., "already exists", "already registered", "duplicate"), you MUST generate a completely NEW, RANDOM, and UNIQUE value for the offending field. DO NOT reuse the value from the Previous Payload or the Available Context.
Ensure the output is ONLY a valid JSON object.
"""
        log.warning(f"\033[93m[LLM Repair]\033[0m Attempting to fix payload for {api_node['id']}")
        
        for attempt in range(self.max_retries):
            try:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": repair_prompt}],
                    response_format={"type": "json_object"},
                    temperature=0.8,
                    max_tokens=512,
                )
                raw = response.choices[0].message.content
                
                # ✅ VALIDATE response với Pydantic
                try:
                    validated = validate_json_response(raw, LLMRepairResponse)
                    parsed = validated
                    log.info(f"[LLM Repair] Fixed payload with {len(parsed)} fields")
                except ValueError as validation_err:
                    log.error(f"[LLM Repair] Validation failed: {validation_err}")
                    return None  # Fallback
                
                # Bỏ qua _randomize_volatile_fields ở đây để tôn trọng tuyệt đối 
                # cách sửa lỗi của LLM (nếu không nó sẽ bị ghi đè lại email cũ từ StateStore)
                return parsed
            except RateLimitError:
                log.warning(f"[LLM Repair] Rate limit — waiting 5s (attempt {attempt})")
                time.sleep(5)
            except Exception as e:
                log.error(f"[LLM Repair] Error: {e}")
                
        return None

    def _heuristic_generate(self, api_node: Dict, state: StateStore, edge_deps: Optional[list] = None) -> Dict:
        dep_map: Dict[str, Any] = {}
        if edge_deps:
            for dep in edge_deps:
                prod = dep.get("producer_field", "")
                cons = dep.get("consumer_field", "")
                prod_norm = self._norm(prod)
                for sk, sv in state.memory.items():
                    if self._norm(sk) == prod_norm:
                        dep_map[self._norm(cons)] = sv
                        break

        payload = {}
        for field_name, meta in api_node.get("inputs", {}).items():
            original  = meta.get("original", field_name) if isinstance(meta, dict) else field_name
            ftype     = meta.get("type", "string") if isinstance(meta, dict) else "string"
            orig_norm = self._norm(original)
            fld_norm  = self._norm(field_name)

            if orig_norm in dep_map:
                payload[original] = dep_map[orig_norm]
            elif fld_norm in dep_map:
                payload[original] = dep_map[fld_norm]
            else:
                matched_val = None
                # Không tự động lôi email cũ ra xài để luôn sinh random email mới,
                # ngoại trừ trường hợp có edge dependency (đã xử lý ở trên).
                if orig_norm != "email" and fld_norm != "email":
                    for sk, sv in state.memory.items():
                        sk_norm = self._norm(sk)
                        if sk_norm == orig_norm or sk_norm == fld_norm:
                            matched_val = sv
                            break
                if matched_val is not None:
                    payload[original] = matched_val
                else:
                    payload[original] = self._default_fuzz_value(ftype, original)

        return payload

    @staticmethod
    def _randomize_volatile_fields(payload: Dict, api_node: Dict, state: StateStore,
                                   dep_map: Optional[Dict] = None) -> Dict:
        """Post-process payload thông minh theo Context (API Type).
        
        dep_map: các field đã được resolve từ ODG edge dep — KHÔNG được randomize đè lên.
        """
        if dep_map is None:
            dep_map = {}
        hex6 = uuid.uuid4().hex[:6]
        hex4 = uuid.uuid4().hex[:4]

        rand_pass = (
            uuid.uuid4().hex[:4].upper()
            + uuid.uuid4().hex[:4]
            + f"@{uuid.uuid4().int % 999 + 1}!"
        )

        path = api_node.get("path", "").lower()
        op_id = api_node.get("id", "").lower()
        combined = path + " " + op_id

        if re.search(r"signup|register|create|add", combined):
            api_type = "CREATE"
        elif re.search(r"login|verify|forgot|reset|auth|signin", combined):
            api_type = "AUTH"
        else:
            api_type = "OTHER"

        out = {}
        for k, v in payload.items():
            if isinstance(v, dict):
                # Đệ quy vào các dictionary con (ví dụ: {"user": {"email": ...}})
                out[k] = LLMPlanner._randomize_volatile_fields(v, api_node, state, dep_map)
                continue
            elif isinstance(v, list):
                # ✅ Xử lý nested list chứa dicts (ví dụ: {"items": [{"email": ...}, {...}]})
                out[k] = [
                    LLMPlanner._randomize_volatile_fields(item, api_node, state, dep_map)
                    if isinstance(item, dict)
                    else item  # Keep non-dict items as-is
                    for item in v
                ]
                continue

            # Nếu field này đã được resolve từ ODG edge dep → giữ nguyên, không randomize
            k_norm = LLMPlanner._norm(k)
            if k_norm in dep_map:
                out[k] = v  # giá trị đã được set đúng từ dep_map, không đụng vào
                log.debug(f"[Randomize] SKIP '{k}' — protected by edge dep (value from StateStore)")
                continue
                
            is_email = LLMPlanner._EMAIL_RE.search(k)
            is_phone = LLMPlanner._PHONE_RE.search(k)
            is_name  = LLMPlanner._NAME_RE.search(k)
            is_pass  = LLMPlanner._PASSWORD_RE.search(k)

            if not (is_email or is_phone or is_name or is_pass):
                out[k] = v
                continue

            if api_type == "CREATE":
                # Luôn sinh mới, bỏ qua State
                if is_email: out[k] = f"fuzz_{hex6}@test.com"
                elif is_phone: out[k] = f"09{uuid.uuid4().int % 100_000_000:08d}"
                elif is_name: out[k] = f"Fuzzer {hex4.upper()}"
                elif is_pass: out[k] = rand_pass
                continue

            # AUTH hoặc OTHER -> Ưu tiên dùng dữ liệu từ StateStore
            matched_val = None
            if is_email: matched_val = state.get("email")
            elif is_pass: matched_val = state.get("password")
            elif is_phone: matched_val = state.get("number") or state.get("phone") or state.get("mobile")
            elif is_name: matched_val = state.get("name") or state.get("username")

            if matched_val is not None:
                out[k] = matched_val
            else:
                # Không có trong Store thì mới sinh mới
                if is_email: out[k] = f"fuzz_{hex6}@test.com"
                elif is_phone: out[k] = f"09{uuid.uuid4().int % 100_000_000:08d}"
                elif is_name: out[k] = f"Fuzzer {hex4.upper()}"
                elif is_pass: out[k] = rand_pass

        return out

    @staticmethod
    def _default_fuzz_value(ftype: str, field_name: str) -> Any:
        if ftype == "integer": return 1
        if ftype == "number": return 0.01
        if ftype == "boolean": return True
        if re.search(r"email", field_name, re.I): return f"fuzz_{uuid.uuid4().hex[:6]}@test.com"
        if re.search(r"phone|mobile|number", field_name, re.I): return "+84900000000"
        if re.search(r"password|pass", field_name, re.I): return "Fuzz@12345!"
        return "fuzz_test_value"
