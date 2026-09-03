"""
attack_store.py
===============
Kho lưu trữ cross-beam dùng cho Reference Forge (step 13 trong sơ đồ).

Mục đích:
  - Thu thập resource IDs (user_id, order_id, vehicleId, ...) từ TẤT CẢ beams
    trong quá trình fuzzing.
  - Cung cấp "foreign IDs" cho Attacker Agent để thử truy cập tài nguyên
    của người khác (BOLA / IDOR).
  - Thread-safe (Lock) vì TestStrategyEngine có thể chạy nhiều beam song song.

Cấu trúc dữ liệu:
  _store: Dict[api_id, List[ResourceEntry]]
    ResourceEntry = {
        "resource_id": "abc123",
        "field_name":  "vehicleId",
        "user_context": {"email": "...", "user_id": "..."},   # ai đã tạo ra resource này
        "endpoint":    "GET /api/v1/vehicles/{vehicleId}",
        "timestamp":   1234567890.0,
    }
"""

import time
import threading
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from reference_engine import (
    ObservedValue,
    ObservedValuePool,
    ProvenanceChain,
    ProvenanceLevel,
    iter_scalar_observations,
)

log = logging.getLogger("attack_store")

# Tối đa số lượng entry lưu cho mỗi api_id
MAX_ENTRIES_PER_API = 50


class AttackStore:
    """
    Singleton-friendly store lưu trữ resource IDs thu được trong quá trình fuzzing.
    Dùng cho Reference Forge: lấy ID của user A để thử truy cập bằng token user B.
    """

    def __init__(self, value_pool: Optional[ObservedValuePool] = None):
        # Deterministic authorization evidence is indexed by the identity of
        # the resource, not by the operation which happened to observe it.
        self._store: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
        self._lock  = threading.Lock()
        self._total = 0
        self.value_pool = value_pool or ObservedValuePool()

    # ── Ghi dữ liệu ──────────────────────────────────────────────────────────

    def record(
        self,
        api_id:      str,
        field_name:  str,
        resource_id: Any,
        endpoint:    str = "",
        user_context: Optional[Dict] = None,
        owner_actor_id: str = "",
        confidence: float = 0.5,
        resource_type: str = "",
        owner_role: str = "",
        provenance: str = "OBSERVED_RESPONSE",
        marker: str = "",
        producer_method: str = "",
        schema: Optional[Dict[str, Any]] = None,
        provenance_chain: Optional[ProvenanceChain] = None,
    ) -> None:
        """
        Lưu một resource ID vào store.

        Args:
            api_id:       ID của API đã trả về resource (vd: "getVehicles")
            field_name:   Tên field chứa ID (vd: "vehicleId", "id", "uuid")
            resource_id:  Giá trị của ID
            endpoint:     URL đầy đủ của request (để debug)
            user_context: Snapshot nhỏ của StateStore (email, user_id, ...)
                          dùng để biết resource này thuộc về ai
        """
        if resource_id is None or resource_id == "":
            return

        context = user_context or {}
        inferred_actor = owner_actor_id or str(context.get("actor_id", ""))
        normalized_type = self.normalize_resource_type(resource_type or api_id)
        selector = self.normalize_selector(field_name, normalized_type)
        key = (normalized_type, selector, inferred_actor)
        chain = provenance_chain or ProvenanceChain.single(
            "resource_store", provenance, confidence,
            relation=normalized_type, actor_id=inferred_actor,
            operation_id=api_id,
        )
        entry = {
            "resource_id":  str(resource_id),
            "resource_value": resource_id,
            "field_name":   field_name,
            "endpoint":     endpoint,
            "producer_api": api_id,
            "owner_actor_id": inferred_actor,
            "ownership_confidence": max(0.0, min(float(confidence), 1.0)),
            "resource_type": normalized_type,
                "selector_field": selector,
                "observed_field": str(field_name),
            "owner_role": str(owner_role or context.get("actor_role", "")),
            # Keep the source label for report/backward compatibility; all
            # eligibility decisions use the normalized effective level below.
            "provenance": str(provenance or "OBSERVED_RESPONSE").upper(),
            "provenance_level": chain.level.name.lower(),
            "provenance_chain": chain.as_dict(),
            "marker": str(marker or ""),
            "producer_method": str(producer_method or "").upper(),
            "user_context": context,
            "timestamp":    time.time(),
        }

        inferred_schema = dict(schema or {})
        if not inferred_schema.get("type"):
            inferred_schema["type"] = (
                "integer" if isinstance(resource_id, int) and not isinstance(resource_id, bool)
                else "number" if isinstance(resource_id, float)
                else "string"
            )
        self.value_pool.observe(ObservedValue(
            value=resource_id,
            schema=inferred_schema,
            location="response",
            field_path=str(field_name),
            provenance=chain,
            operation_id=api_id,
            actor_id=inferred_actor,
            relationship=normalized_type,
        ))

        with self._lock:
            if key not in self._store:
                self._store[key] = []

            bucket = self._store[key]

            # Preserve provenance when the same value appears under different
            # selectors or actors. Authorization evidence is actor-relative.
            if any(
                e["resource_id"] == str(resource_id)
                and e.get("field_name") == field_name
                and e.get("owner_actor_id", "") == inferred_actor
                for e in bucket
            ):
                return

            # Giới hạn kích thước
            if len(bucket) >= MAX_ENTRIES_PER_API:
                bucket.pop(0)

            bucket.append(entry)
            self._total += 1
            log.debug(
                f"[AttackStore] record api={api_id} field={field_name} id={resource_id}"
            )

    def record_from_response(
        self,
        api_id:       str,
        response_json: Any,
        endpoint:     str = "",
        user_context: Optional[Dict] = None,
        id_fields:    Optional[List[str]] = None,
        owner_actor_id: str = "",
        confidence: float = 0.5,
        resource_type: str = "",
        owner_role: str = "",
        provenance: str = "OBSERVED_RESPONSE",
        marker: str = "",
        producer_method: str = "",
    ) -> int:
        """
        Tự động harvest các field ID từ response JSON và lưu vào store.

        Args:
            id_fields: Resource-selector whitelist derived from OpenAPI. It may
                       contain natural keys such as username, title or slug.
                       If None, fall back to conventional ID detection.

        Returns:
            Số lượng entry mới được lưu
        """
        if not response_json:
            return 0

        import re as _re
        _ID_PATTERN = _re.compile(r"(_id|Id|uuid|_ref|Ref|_code|vin)$", _re.I)

        def _harvest(obj, count=0):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (str, int)) and v:
                        should_record = (
                            (id_fields and k in id_fields)
                            or (not id_fields and _ID_PATTERN.search(k))
                        )
                        if should_record:
                            self.record(
                                api_id, k, v, endpoint, user_context,
                                owner_actor_id=owner_actor_id,
                                confidence=confidence,
                                resource_type=resource_type,
                                owner_role=owner_role,
                                provenance=provenance,
                                marker=marker,
                                producer_method=producer_method,
                            )
                            count += 1
                    elif isinstance(v, dict):
                        count = _harvest(v, count)
                    elif isinstance(v, list):
                        for item in v:
                            count = _harvest(item, count)
            elif isinstance(obj, list):
                for item in obj:
                    count = _harvest(item, count)
            return count

        return _harvest(response_json)

    # ── Đọc dữ liệu ──────────────────────────────────────────────────────────

    def get_foreign_ids(
        self,
        api_id:       str,
        own_context:  Optional[Dict] = None,
        field_name:   Optional[str]  = None,
        limit:        int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Trả về các resource IDs KHÔNG thuộc về `own_context` (foreign IDs).

        Dùng cho Reference Forge: lấy ID của người khác để test BOLA.

        Args:
            api_id:      API cần lấy IDs
            own_context: Context của user hiện tại (email, user_id, ...).
                         Dùng để lọc bỏ các ID thuộc về chính user này.
            field_name:  Lọc theo tên field cụ thể (optional)
            limit:       Số lượng tối đa trả về

        Returns:
            List[dict]: Danh sách entry phù hợp
        """
        requested_type = self.normalize_resource_type(api_id)
        with self._lock:
            canonical_field = self.normalize_selector(field_name, requested_type) if field_name else ""
            bucket = [
                entry for (rtype, selector, _owner), entries in self._store.items()
                if rtype == requested_type and (not canonical_field or selector == canonical_field)
                for entry in entries
            ]

        results = []
        own_user_id  = str(own_context.get("user_id", "")) if own_context else ""
        own_email    = str(own_context.get("email", "")).lower() if own_context else ""
        own_actor_id = str(own_context.get("actor_id", "")) if own_context else ""

        for entry in reversed(bucket):  # Ưu tiên entry mới nhất
            # Lọc theo field_name nếu có
            if field_name and entry["field_name"] != field_name:
                continue

            # Loại bỏ ID của chính mình
            ctx = entry.get("user_context", {})
            entry_actor_id = str(entry.get("owner_actor_id", ""))
            if own_actor_id and entry_actor_id == own_actor_id:
                continue
            if own_user_id and str(ctx.get("user_id", "")) == own_user_id:
                continue
            if own_email and str(ctx.get("email", "")).lower() == own_email:
                continue

            # With an identified current actor, unknown ownership is not proof
            # of a foreign resource. Keep it out of high-confidence BOLA tests.
            has_owner_evidence = bool(
                entry_actor_id or ctx.get("user_id") or ctx.get("email")
            )
            if own_actor_id and not has_owner_evidence:
                continue

            results.append(entry)
            if len(results) >= limit:
                break

        return results

    def get_foreign_resources(
        self,
        resource_type: str,
        selector_field: str,
        attacker_actor_id: str,
        attacker_role: str = "",
        limit: int = 5,
        require_created: bool = True,
    ) -> List[Dict[str, Any]]:
        """Return authoritative foreign resources for comparable principals.

        Explicit roles must match. When neither side declares a role, distinct
        authenticated principals remain eligible for role-less APIs.
        """
        normalized_attacker_role = str(attacker_role or "").strip().casefold()
        unknown_roles = {"", "unknown", "anonymous", "none", "null"}
        key_type = self.normalize_resource_type(resource_type)
        canonical_selector = self.normalize_selector(selector_field, key_type)
        with self._lock:
            candidates = [
                entry for (rtype, selector, owner), entries in self._store.items()
                if rtype == key_type and selector == canonical_selector
                and owner and owner != str(attacker_actor_id)
                for entry in entries
            ]
        results = []
        for entry in sorted(candidates, key=lambda item: item["timestamp"], reverse=True):
            if require_created and ProvenanceLevel.parse(
                entry.get("provenance_chain", {}).get("level", entry.get("provenance_level", entry.get("provenance")))
            ) < ProvenanceLevel.AUTHORITATIVE:
                continue
            owner_role = str(entry.get("owner_role", "")).strip().casefold()
            attacker_role_known = normalized_attacker_role not in unknown_roles
            owner_role_known = owner_role not in unknown_roles
            if attacker_role_known != owner_role_known:
                continue
            roles_known = attacker_role_known and owner_role_known
            if roles_known and owner_role != normalized_attacker_role:
                continue
            results.append(dict(entry))
            if len(results) >= limit:
                break
        return results

    def invalidate(
        self,
        resource_type: str,
        selector_field: str,
        resource_id: Any,
        owner_actor_id: str = "",
    ) -> int:
        """Remove a resource proven deleted by a successful owner workflow."""
        key_type = self.normalize_resource_type(resource_type)
        selector = self.normalize_selector(selector_field, key_type)
        removed = 0
        with self._lock:
            for key in list(self._store):
                rtype, stored_selector, owner = key
                if rtype != key_type or stored_selector != selector:
                    continue
                if owner_actor_id and owner != str(owner_actor_id):
                    continue
                before = len(self._store[key])
                self._store[key] = [
                    entry for entry in self._store[key]
                    if str(entry.get("resource_id")) != str(resource_id)
                ]
                removed += before - len(self._store[key])
                if not self._store[key]:
                    self._store.pop(key, None)
            self._total = max(0, self._total - removed)
        return removed

    def get_all_ids_for_api(self, api_id: str) -> List[Dict[str, Any]]:
        """Trả về TẤT CẢ entries cho một api_id (kể cả của chính mình)."""
        with self._lock:
            requested_type = self.normalize_resource_type(api_id)
            return [
                entry for (rtype, _selector, _owner), entries in self._store.items()
                if rtype == requested_type for entry in entries
            ]

    def get_candidate_ids(
        self,
        field_name: str,
        own_id:     Any,
        limit:      int = 10,
    ) -> List[Any]:
        """
        Sinh danh sách candidate IDs để thử cho ID Substitution.

        Chiến lược:
          1. Foreign IDs từ store (thực)
          2. own_id ± delta (adjacent IDs)
          3. Boundary values (0, -1, 999999, ...)
        """
        candidates = set()

        # 1. Foreign IDs từ store
        with self._lock:
            for bucket in self._store.values():
                for entry in bucket:
                    if entry["field_name"] == field_name:
                        if str(entry["resource_id"]) != str(own_id):
                            candidates.add(entry["resource_id"])
                            if len(candidates) >= limit:
                                break

        # 2. Adjacent integer IDs nếu own_id là số
        try:
            oid = int(own_id)
            for delta in [-1, 1, -2, 2, 3, -3, 100, 1000]:
                cid = oid + delta
                if cid > 0:
                    candidates.add(str(cid))
        except (ValueError, TypeError):
            pass

        # 3. Boundary values
        for bv in ["0", "1", "-1", "admin", "null", "undefined", "99999"]:
            if bv != str(own_id):
                candidates.add(bv)

        result = list(candidates)[:limit]
        log.debug(f"[AttackStore] candidate IDs for field={field_name}: {result}")
        return result

    def observe_operation(
        self,
        operation: Dict[str, Any],
        request_values: Optional[Dict[str, Any]] = None,
        response_value: Any = None,
        actor_id: str = "",
        successful: bool = True,
    ) -> None:
        """Harvest schema-linked request and response values from this run."""
        operation_id = str(operation.get("id", ""))
        relationship = self.normalize_resource_type(
            operation.get("resource_type") or operation.get("path") or operation_id
        )
        request_values = request_values or {}
        for normalized, raw_schema in (operation.get("inputs", {}) or {}).items():
            schema = dict(raw_schema) if isinstance(raw_schema, dict) else {}
            name = str(schema.get("original", normalized))
            path = str(schema.get("json_path") or name)
            value = self._value_from_request(request_values, schema.get("in", "body"), name, path)
            if value in (None, "") or isinstance(value, (dict, list)):
                continue
            self.value_pool.observe(ObservedValue(
                value=value, schema=schema, location=str(schema.get("in", "body")),
                field_path=path,
                provenance=ProvenanceChain.single(
                    "successful_request" if successful else "attempted_request",
                    ProvenanceLevel.OBSERVED if successful else ProvenanceLevel.DERIVED,
                    0.75 if successful else 0.35, relation=relationship,
                    actor_id=actor_id, operation_id=operation_id,
                ),
                operation_id=operation_id, actor_id=actor_id,
                relationship=relationship,
            ))

        output_by_path = {
            str(meta.get("json_path")): dict(meta)
            for meta in (operation.get("outputs", {}) or {}).values()
            if isinstance(meta, dict) and meta.get("json_path")
        }
        for path, value in iter_scalar_observations(response_value):
            schema = output_by_path.get(path, {})
            if not schema:
                schema = {
                    "type": "boolean" if isinstance(value, bool)
                    else "integer" if isinstance(value, int)
                    else "number" if isinstance(value, float)
                    else "string"
                }
            self.value_pool.observe(ObservedValue(
                value=value, schema=schema, location="response", field_path=path,
                provenance=ProvenanceChain.single(
                    "successful_response", ProvenanceLevel.OBSERVED, 0.8,
                    relation=relationship, actor_id=actor_id,
                    operation_id=operation_id,
                ),
                operation_id=operation_id, actor_id=actor_id,
                relationship=relationship,
            ))

    @staticmethod
    def _value_from_request(values: Dict[str, Any], location: str, name: str, path: str) -> Any:
        if str(location).lower() != "body":
            return values.get(name, values.get(path))
        current: Any = values
        for part in [part for part in re.split(r"\.|\[\]", path) if part]:
            if isinstance(current, list):
                current = current[0] if current else None
            if not isinstance(current, dict):
                return values.get(name)
            current = current.get(part)
        return current

    # ── Stats & Debug ─────────────────────────────────────────────────────────

    @property
    def total_entries(self) -> int:
        return self._total

    def stats(self) -> Dict[str, int]:
        """Return counts by stable resource/selector/owner key."""
        with self._lock:
            return {"|".join(k): len(v) for k, v in self._store.items()}

    def export_snapshot(self) -> Dict[str, Any]:
        """Export toàn bộ store để ghi vào báo cáo."""
        with self._lock:
            return {
                "total_entries": self._total,
                "by_resource": {"|".join(k): list(v) for k, v in self._store.items()},
            }

    def __repr__(self) -> str:
        return f"AttackStore(total={self._total}, resources={list(self._store.keys())})"

    @staticmethod
    def normalize_resource_type(value: str) -> str:
        """Normalize operation ids and paths into a reusable resource family."""
        text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or "")).lower()
        text = re.sub(r"\{[^}]+\}", "", text)
        tokens = [t for t in re.split(r"[^a-z0-9]+", text) if t]
        actions = {
            "create", "add", "new", "post", "get", "fetch", "read", "list",
            "find", "update", "edit", "modify", "patch", "delete", "remove",
            "api", "v1", "v2", "v3",
        }
        meaningful = [token for token in tokens if token not in actions]
        resource = meaningful[-1] if meaningful else (tokens[-1] if tokens else "resource")
        return resource[:-1] if len(resource) > 3 and resource.endswith("s") else resource

    @staticmethod
    def normalize_selector(value: str, resource_type: str = "") -> str:
        selector = re.sub(r"[^a-z0-9]", "", str(value or "").casefold())
        prefix = re.sub(r"[^a-z0-9]", "", str(resource_type or "").casefold())
        if prefix and selector.startswith(prefix):
            selector = selector[len(prefix):]
        return selector or "id"


# ── Singleton dùng chung toàn project ─────────────────────────────────────────
_global_attack_store: Optional[AttackStore] = None


def get_attack_store() -> AttackStore:
    global _global_attack_store
    if _global_attack_store is None:
        _global_attack_store = AttackStore()
    return _global_attack_store
