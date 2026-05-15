import os
import json
import re
import time
import logging
from typing import Any, Dict, Optional, List
from openai import OpenAI, RateLimitError, APIError
from dotenv import load_dotenv
from state_store import StateStore

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
    def __init__(self):
        self.github_token = os.getenv("GITHUB_TOKEN", "")
        self.endpoint = "https://models.github.ai/inference"
        self.model = "gpt-4o-mini"
        self.max_retries = 2
        
        if not self.github_token:
            log.warning("[LLMPlanner] GITHUB_TOKEN chưa set — sẽ dùng heuristic fallback.")
        self._client = OpenAI(
            base_url=self.endpoint,
            api_key=self.github_token,
        ) if self.github_token else None

        self._llm_cache = {}
        self._identity_cluster_map = {}

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
            result = json.loads(response.choices[0].message.content)
            log.info(f"  [LLM] GitHub Models (gpt-4o-mini) OK")
            
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
            raw = json.loads(response.choices[0].message.content)
            clusters = raw.get('clusters', [])
            if not isinstance(clusters, list):
                clusters = next((v for v in raw.values() if isinstance(v, list)), [])

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

    def generate_payload(self, api_node: Dict, state: StateStore, edge_deps: Optional[list] = None) -> Dict[str, Any]:
        method = api_node.get("method", "GET").upper()
        if method in ("GET", "DELETE"):
            return {}

        source = "LLM"
        payload = self._llm_generate(api_node, state, edge_deps=edge_deps)
        if payload is None:
            source = "HEURISTIC"
            payload = self._heuristic_generate(api_node, state, edge_deps=edge_deps)

        if source == "LLM":
            log.info(f"\033[95m[LLM Payload]\033[0m {api_node['id']} → {json.dumps(payload, ensure_ascii=False)[:200]}")
        else:
            log.info(f"\033[93m[HEURISTIC Payload]\033[0m {api_node['id']} → {json.dumps(payload, ensure_ascii=False)[:200]}")
            
        return payload

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

        AUTH_KEYS = {"auth_token", "token_type", "user_role"}
        context_lines = []
        for k, v in state.memory.items():
            if k in AUTH_KEYS:
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
- For missing fields, generate realistic synthetic data (e.g. standard emails, safe passwords).
"""
        return prompt

    def _llm_generate(self, api_node: Dict, state: StateStore, edge_deps: Optional[list] = None) -> Optional[Dict]:
        if not self._client:
            return None
        prompt = self._build_prompt(api_node, state, edge_deps)
        
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
                return json.loads(raw)
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
    def _default_fuzz_value(ftype: str, field_name: str) -> Any:
        if ftype == "integer": return 1
        if ftype == "number": return 0.01
        if ftype == "boolean": return True
        if re.search(r"email", field_name, re.I): return "fuzz@test.com"
        if re.search(r"phone|mobile|number", field_name, re.I): return "+84900000000"
        if re.search(r"password|pass", field_name, re.I): return "Fuzz@12345!"
        return "fuzz_test_value"
