"""
attacker_agent.py
=================
Attacker Agent chạy Qwen2.5-Coder 7B để thực hiện 3 chiến lược tấn công BOLA/IDOR
(Steps 11, 12, 13 trong sơ đồ):

  11. ID Substitution    — Thay thế ID của mình bằng ID của người khác
  12. Parameter Pollution — Nhồi thêm/trùng lặp parameter để bypass validation
  13. Reference Forge    — Forge tham chiếu đến resource của người khác

Mỗi chiến lược trả về List[AttackVariant] — danh sách các biến thể request
để TestStrategyEngine thực thi và ghi kết quả.
"""

import copy
import json
import logging
import re
from typing import Any, Dict, List, Optional

from ollama_client import OllamaClient, get_ollama_client, OLLAMA_ENABLED
from attack_store import AttackStore, get_attack_store
from state_store import StateStore
from reference_engine import (
    ProvenanceLevel,
    ReferenceDiscovery,
    RequestTransformer,
)

log = logging.getLogger("attacker_agent")


class AttackVariant:
    """
    Một biến thể tấn công: bản sao của API node với path/payload đã bị biến đổi.
    """
    def __init__(
        self,
        strategy:    str,          # "id_substitution" | "param_pollution" | "reference_forge"
        api_node:    Dict,         # dict copy của api_node gốc
        payload:     Dict,         # payload đã biến đổi
        path:        str,          # path đã giải quyết (có thể đã thay ID)
        description: str = "",     # mô tả ngắn gọn để log
        extra:       Dict = None,  # metadata bổ sung
    ):
        self.strategy    = strategy
        self.api_node    = api_node
        self.payload     = payload
        self.path        = path
        self.description = description
        self.extra       = extra or {}

    def __repr__(self):
        return f"AttackVariant(strategy={self.strategy}, path={self.path}, desc={self.description[:60]})"


class AttackerAgent:
    """
    Attacker Agent: Qwen2.5-Coder 7B.

    Điều phối 3 chiến lược tấn công, trả về danh sách AttackVariant
    để TestStrategyEngine thực thi qua RequestExecutor.
    """

    SYSTEM_PROMPT = (
        "You are an expert API penetration tester specializing in BOLA/IDOR vulnerabilities. "
        "Your task is to generate attack payloads to test if an API improperly authorizes "
        "access to other users' resources. Be precise and technical."
    )

    def __init__(
        self,
        client:       Optional[OllamaClient] = None,
        attack_store: Optional[AttackStore]  = None,
        max_variants: int = 3,   # Tối đa bao nhiêu variant mỗi strategy
    ):
        self.client       = client or get_ollama_client()
        self.attack_store = attack_store or get_attack_store()
        self.max_variants = max_variants
        self.reference_discovery = ReferenceDiscovery(self.attack_store.value_pool)
        self.generation_errors: List[Dict[str, str]] = []

    # ── Entry point chính ─────────────────────────────────────────────────────

    def generate_attacks(
        self,
        api_node:     Dict,
        state:        StateStore,
        valid_payload: Dict,
        valid_response: Optional[Dict] = None,
    ) -> List[AttackVariant]:
        """
        Sinh toàn bộ attack variants cho một API node.
        Chạy cả 3 chiến lược và gộp kết quả.

        Args:
            api_node:       Thông tin API (id, path, method, inputs, outputs)
            state:          StateStore hiện tại (có own_id, email, ...)
            valid_payload:  Payload hợp lệ đã gửi thành công (2xx)
            valid_response: Response JSON từ lần gọi hợp lệ (optional, dùng cho Baseline)

        Returns:
            List[AttackVariant] — tất cả variants để thực thi
        """
        api_id = api_node.get("id", "unknown")
        log.info(f"\033[95m[AttackerAgent]\033[0m Generating attacks for {api_id}")

        variants: List[AttackVariant] = []
        self.generation_errors = []

        # ── Chiến lược 11: ID Substitution ────────────────────────────────────
        try:
            id_subs = self._id_substitution(api_node, state, valid_payload)
            variants.extend(id_subs)
            log.info(f"[AttackerAgent] ID Substitution → {len(id_subs)} variants")
        except Exception as e:
            error = {"stage": "generation_failed", "strategy": "reference_transform", "reason": f"{type(e).__name__}: {e}"}
            self.generation_errors.append(error)
            log.exception(f"[AttackerAgent] ID Substitution error: {e}")

        # ── Chiến lược 12: Parameter Pollution ────────────────────────────────
        try:
            param_polls = self._parameter_pollution(api_node, state, valid_payload)
            variants.extend(param_polls)
            log.info(f"[AttackerAgent] Parameter Pollution → {len(param_polls)} variants")
        except Exception as e:
            error = {"stage": "generation_failed", "strategy": "parameter_pollution", "reason": f"{type(e).__name__}: {e}"}
            self.generation_errors.append(error)
            log.exception(f"[AttackerAgent] Parameter Pollution error: {e}")

        # ── Chiến lược 13: Reference Forge ────────────────────────────────────
        try:
            ref_forges = self._reference_forge(api_node, state, valid_payload)
            variants.extend(ref_forges)
            log.info(f"[AttackerAgent] Reference Forge → {len(ref_forges)} variants")
        except Exception as e:
            error = {"stage": "generation_failed", "strategy": "foreign_reference", "reason": f"{type(e).__name__}: {e}"}
            self.generation_errors.append(error)
            log.exception(f"[AttackerAgent] Reference Forge error: {e}")

        log.info(f"[AttackerAgent] Total variants: {len(variants)}")
        return variants

    # ── Chiến lược 11: ID Substitution ────────────────────────────────────────

    def _id_substitution(
        self,
        api_node: Dict,
        state:    StateStore,
        payload:  Dict,
    ) -> List[AttackVariant]:
        """
        Phát hiện các field ID trong path/payload và thay bằng ID của người khác.

        Ví dụ:
          /api/v1/users/42/profile  →  /api/v1/users/43/profile
          {"user_id": 42}           →  {"user_id": 43}
        """
        variants = []
        actor_id = str(state.get("actor_id", "default"))
        discovered = self.reference_discovery.discover(api_node, payload, actor_id)
        for reference in discovered:
            for observed in reference.candidate_values[:self.max_variants]:
                new_node, new_payload = RequestTransformer.transform(
                    api_node, payload, reference, observed.value
                )
                variants.append(AttackVariant(
                    strategy="id_substitution",
                    api_node=new_node,
                    payload=new_payload,
                    path=new_node.get("path", api_node.get("path", "")),
                    description=(
                        f"Reference substitution at {reference.location}:"
                        f"{reference.field_path}"
                    ),
                    extra={
                        "field": reference.parameter_name,
                        "field_path": reference.field_path,
                        # All deterministic authorization probes expose the same
                        # canonical identity contract, regardless of how the
                        # replacement value was discovered.
                        "selector_field": reference.parameter_name or reference.field_path,
                        "resource_id": observed.value,
                        "resource_type": (
                            observed.relationship
                            or api_node.get("resource_type")
                            or api_node.get("path")
                            or api_node.get("id", "")
                        ),
                        "location": reference.location,
                        "original_id": reference.original_value,
                        "substitute_id": observed.value,
                        "provenance": observed.provenance.level.name,
                        "provenance_chain": observed.provenance.as_dict(),
                        "reference_confidence": reference.confidence,
                        "confirmation_eligible": bool(
                            observed.actor_id
                            and observed.actor_id != actor_id
                            and observed.provenance.level >= ProvenanceLevel.AUTHORITATIVE
                        ),
                        "owner_actor_id": observed.actor_id,
                        "producer_api": observed.operation_id,
                    },
                ))
                if len(variants) >= self.max_variants:
                    return variants
        return variants

    def _llm_identify_id_fields(self, api_node: Dict, known_fields: List[str]) -> List[str]:
        """Dùng Qwen để phát hiện thêm field ID không rõ ràng."""
        if not OLLAMA_ENABLED:
            return []
        schema = {
            k: (v if isinstance(v, dict) else {"type": "unknown"})
            for k, v in api_node.get("inputs", {}).items()
        }
        if not schema:
            return []

        prompt = f"""API endpoint: {api_node.get('method')} {api_node.get('path')}
Schema: {json.dumps(schema, indent=2)}
Already identified ID fields: {known_fields}

Which additional fields in this schema are resource identifiers (IDs, UUIDs, references) 
that could be used for BOLA/IDOR testing?

Respond with JSON: {{"id_fields": ["field1", "field2"]}}"""

        result = self.client.attacker(prompt, system=self.SYSTEM_PROMPT, temperature=0.1)
        if result and isinstance(result.get("id_fields"), list):
            return [f for f in result["id_fields"] if isinstance(f, str)]
        return []

    # ── Chiến lược 12: Parameter Pollution ────────────────────────────────────

    def _parameter_pollution(
        self,
        api_node: Dict,
        state:    StateStore,
        payload:  Dict,
    ) -> List[AttackVariant]:
        """
        HTTP Parameter Pollution & Type Confusion.

        Kỹ thuật:
          A) Duplicate key: gửi cùng 1 field 2 lần với giá trị khác nhau
             Server nhận giá trị nào? (đầu tiên hay cuối cùng?)
          B) Role escalation: thêm field role=admin, isAdmin=true vào body
          C) Type confusion: string→int, array→scalar, nested object injection
        """
        method   = api_node.get("method", "GET").upper()
        variants = []

        if method not in ("POST", "PUT", "PATCH"):
            # Read-only and DELETE operations cannot demonstrate a body-field
            # mass assignment. Limit them to transport-level query pollution.
            variants.extend(self._pollution_query_params(api_node, state))
            return variants

        # A) Privilege escalation fields
        priv_fields = self._llm_generate_privilege_fields(api_node, payload)
        if priv_fields:
            new_payload = copy.deepcopy(payload)
            new_payload.update(priv_fields)
            variants.append(AttackVariant(
                strategy="param_pollution",
                api_node=dict(api_node),
                payload=new_payload,
                path=api_node.get("path", ""),
                description=f"Privilege escalation fields: {list(priv_fields.keys())}",
                extra={"technique": "privilege_escalation", "injected": priv_fields},
            ))

        # B) Duplicate key — chèn user_id khác sau own user_id
        own_id = state.get("user_id") or state.get("id")
        _ID_RE = re.compile(r"(_id|Id|_uuid)$", re.I)
        for k, v in payload.items():
            if _ID_RE.search(k) and own_id:
                new_payload = copy.deepcopy(payload)
                # Thêm key trùng tên với value là adjacent ID
                try:
                    foreign_id = str(int(own_id) + 1)
                except (ValueError, TypeError):
                    foreign_id = "1"
                new_payload[f"__{k}"] = foreign_id   # Double-underscore trick
                # Gửi cả 2 (nhiều framework lấy giá trị cuối)
                new_payload[k] = [v, foreign_id]  # Array injection
                variants.append(AttackVariant(
                    strategy="param_pollution",
                    api_node=dict(api_node),
                    payload=new_payload,
                    path=api_node.get("path", ""),
                    description=f"Duplicate key injection: {k}=[{v}, {foreign_id}]",
                    extra={"technique": "duplicate_key", "field": k},
                ))
                break  # Chỉ làm với field đầu tiên tìm được

        # C) Mass Assignment — thêm toàn bộ field nhạy cảm
        mass_payload = copy.deepcopy(payload)
        mass_fields = {
            "role": "admin",
            "isAdmin": True,
            "is_admin": True,
            "admin": True,
            "userRole": "ADMIN",
            "permissions": ["*"],
        }
        mass_payload.update(mass_fields)
        variants.append(AttackVariant(
            strategy="param_pollution",
            api_node=dict(api_node),
            payload=mass_payload,
            path=api_node.get("path", ""),
            description="Mass assignment: role=admin injection",
            extra={"technique": "mass_assignment", "injected": mass_fields},
        ))

        return variants[:self.max_variants]

    def _pollution_query_params(self, api_node: Dict, state: StateStore) -> List[AttackVariant]:
        """Pollution cho GET request (query string)."""
        variants = []
        path = api_node.get("path", "")
        # Thêm query params nhạy cảm
        for qs in ["?role=admin", "?isAdmin=true", "?debug=1", "?admin=true"]:
            variants.append(AttackVariant(
                strategy="param_pollution",
                api_node=dict(api_node),
                payload={},
                path=path + qs,
                description=f"Query param injection: {qs}",
                extra={"technique": "query_pollution"},
            ))
        return variants[:self.max_variants]

    def _llm_generate_privilege_fields(self, api_node: Dict, payload: Dict) -> Dict:
        """Dùng Qwen để sinh privilege escalation fields phù hợp với context."""
        if not OLLAMA_ENABLED:
            return {"role": "admin", "isAdmin": True}
        prompt = f"""API: {api_node.get('method')} {api_node.get('path')}
Current payload fields: {list(payload.keys())}

Generate additional JSON fields that could cause privilege escalation or authorization bypass 
if the server doesn't properly validate them (e.g., role, isAdmin, permissions).
Return only fields likely to be accepted by this specific API.

Respond with JSON: {{"privilege_fields": {{"field_name": "value"}}}}"""

        result = self.client.attacker(prompt, system=self.SYSTEM_PROMPT, temperature=0.3)
        if result and isinstance(result.get("privilege_fields"), dict):
            return result["privilege_fields"]
        return {"role": "admin", "isAdmin": True}   # Fallback mặc định

    # ── Chiến lược 13: Reference Forge ────────────────────────────────────────

    def _reference_forge(
        self,
        api_node: Dict,
        state:    StateStore,
        payload:  Dict,
    ) -> List[AttackVariant]:
        """
        Forge tham chiếu đến resource của người khác bằng cách dùng ID
        lấy từ AttackStore (thu thập từ các beam khác).

        Ví dụ:
          GET /api/documents/{docId}
          Lấy docId của user khác từ AttackStore và gửi request
        """
        api_id   = api_node.get("id", "")
        path     = api_node.get("path", "")
        variants = []

        own_context = {
            "actor_id": state.get("actor_id", "default"),
            "user_id": state.get("user_id") or state.get("id"),
            "email":   state.get("email"),
        }

        selectors = list(api_node.get("resource_selectors", []) or [])
        selectors.extend(re.findall(r"\{([^}]+)\}", path))
        # Nested resources are authorized by the leaf selector. For example,
        # /memo/{memoId}/resource/{resourceId} must forge resourceId, which is
        # also the selector chosen by AuthorizationExperimentPlanner.
        selector = selectors[-1] if selectors else ""
        resource_type = api_node.get("resource_type") or path or api_id

        # Only a created resource with an identified foreign same-role owner is
        # eligible for deterministic BOLA confirmation.
        foreign_entries = self.attack_store.get_foreign_resources(
            resource_type=resource_type,
            selector_field=selector,
            attacker_actor_id=own_context["actor_id"],
            attacker_role=state.get("actor_role", ""),
            limit=self.max_variants,
        )

        # Nếu không có trong store, dùng LLM để sinh ID mồi
        if not foreign_entries:
            forged_ids = self._llm_forge_ids(api_node, state)
            for fid in forged_ids[:self.max_variants]:
                # Thay tất cả path params bằng forged ID
                new_path = re.sub(r"\{[^}]+\}", str(fid), path)
                variants.append(AttackVariant(
                    strategy="reference_forge",
                    api_node=dict(api_node),
                    payload=copy.deepcopy(payload),
                    path=new_path,
                    description=f"Reference Forge (LLM-forged): id={fid}",
                    extra={
                        "technique": "llm_forge", "forged_id": fid,
                        "provenance": "GUESSED", "confirmation_eligible": False,
                    },
                ))
        else:
            for entry in foreign_entries:
                field_name  = entry["field_name"]
                resource_id = entry.get("resource_value", entry["resource_id"])
                unknown_roles = {"", "unknown", "anonymous", "none", "null"}
                owner_role = str(entry.get("owner_role", "")).strip().casefold()
                attacker_role = str(state.get("actor_role", "")).strip().casefold()
                actor_relationship = (
                    "same_role_distinct_principals"
                    if owner_role not in unknown_roles
                    and attacker_role not in unknown_roles
                    and owner_role == attacker_role
                    else "distinct_authenticated_principals"
                    if owner_role in unknown_roles and attacker_role in unknown_roles
                    else "cross_role_distinct_principals"
                )

                # Thay path param
                new_path = re.sub(
                    r"\{" + re.escape(field_name) + r"\}",
                    str(resource_id),
                    path,
                )
                # Nếu không khớp path param, thay tất cả path params còn lại
                if new_path == path:
                    new_path = re.sub(r"\{[^}]+\}", str(resource_id), path)

                new_payload = copy.deepcopy(payload)
                if field_name in new_payload:
                    new_payload[field_name] = resource_id

                variants.append(AttackVariant(
                    strategy="reference_forge",
                    api_node=dict(api_node),
                    payload=new_payload,
                    path=new_path,
                    description=(
                        f"Reference Forge: {field_name}={resource_id} "
                        f"(from {entry.get('user_context', {}).get('email', 'unknown')})"
                    ),
                    extra={
                        "technique":   "cross_user_reference",
                        "field":       field_name,
                        "resource_id": resource_id,
                        "owner_ctx":   entry.get("user_context", {}),
                        "owner_actor_id": entry.get("owner_actor_id", ""),
                        "owner_role": entry.get("owner_role", ""),
                        "actor_relationship": actor_relationship,
                        "resource_type": entry.get("resource_type", ""),
                        "producer_api": entry.get("producer_api", ""),
                        "selector_field": entry.get("selector_field", field_name),
                        "provenance": entry.get("provenance", ""),
                        "marker": entry.get("marker", ""),
                        "confirmation_eligible": entry.get("provenance") == "CREATED_RESPONSE",
                    },
                ))

        return variants[:self.max_variants]

    def _llm_forge_ids(self, api_node: Dict, state: StateStore) -> List[str]:
        """Dùng Qwen để sinh các ID mồi khi AttackStore trống."""
        own_id = state.get("user_id") or state.get("id") or "1"

        if not OLLAMA_ENABLED:
            try:
                oid = int(own_id)
                return [str(oid + 1), str(max(1, oid - 1)), "1", "2"]
            except (ValueError, TypeError):
                return ["1", "2", "admin"]

        prompt = f"""API endpoint: {api_node.get('method')} {api_node.get('path')}
Own user ID: {own_id}

Generate a list of plausible resource IDs that might belong to OTHER users 
to test BOLA/IDOR vulnerabilities. Consider:
- Sequential IDs (own ± small delta)
- Common admin IDs (1, 2, admin)
- UUID-like strings if path suggests UUIDs

Respond with JSON: {{"forged_ids": ["id1", "id2", "id3"]}}"""

        result = self.client.attacker(prompt, system=self.SYSTEM_PROMPT, temperature=0.5)
        if result and isinstance(result.get("forged_ids"), list):
            return [str(i) for i in result["forged_ids"]]

        # Fallback: adjacent IDs
        try:
            oid = int(own_id)
            return [str(oid + 1), str(oid - 1), "1", "2"]
        except (ValueError, TypeError):
            return ["1", "2", "admin"]
