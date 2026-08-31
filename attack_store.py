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
from typing import Any, Dict, List, Optional

log = logging.getLogger("attack_store")

# Tối đa số lượng entry lưu cho mỗi api_id
MAX_ENTRIES_PER_API = 50


class AttackStore:
    """
    Singleton-friendly store lưu trữ resource IDs thu được trong quá trình fuzzing.
    Dùng cho Reference Forge: lấy ID của user A để thử truy cập bằng token user B.
    """

    def __init__(self):
        self._store: Dict[str, List[Dict[str, Any]]] = {}
        self._lock  = threading.Lock()
        self._total = 0

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
        entry = {
            "resource_id":  str(resource_id),
            "field_name":   field_name,
            "endpoint":     endpoint,
            "producer_api": api_id,
            "owner_actor_id": inferred_actor,
            "ownership_confidence": max(0.0, min(float(confidence), 1.0)),
            "user_context": context,
            "timestamp":    time.time(),
        }

        with self._lock:
            if api_id not in self._store:
                self._store[api_id] = []

            bucket = self._store[api_id]

            # Dedup: không lưu cùng resource_id hai lần cho cùng api
            if any(e["resource_id"] == str(resource_id) for e in bucket):
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
    ) -> int:
        """
        Tự động harvest các field ID từ response JSON và lưu vào store.

        Args:
            id_fields: Whitelist field names cần harvest.
                       Nếu None → dùng auto-detection (tên chứa "id", "uuid", "ref").

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
        with self._lock:
            bucket = self._store.get(api_id, [])

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

    def get_all_ids_for_api(self, api_id: str) -> List[Dict[str, Any]]:
        """Trả về TẤT CẢ entries cho một api_id (kể cả của chính mình)."""
        with self._lock:
            return list(self._store.get(api_id, []))

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

    # ── Stats & Debug ─────────────────────────────────────────────────────────

    @property
    def total_entries(self) -> int:
        return self._total

    def stats(self) -> Dict[str, int]:
        """Trả về số lượng entry per api_id."""
        with self._lock:
            return {k: len(v) for k, v in self._store.items()}

    def export_snapshot(self) -> Dict[str, Any]:
        """Export toàn bộ store để ghi vào báo cáo."""
        with self._lock:
            return {
                "total_entries": self._total,
                "by_api": {k: list(v) for k, v in self._store.items()},
            }

    def __repr__(self) -> str:
        return f"AttackStore(total={self._total}, apis={list(self._store.keys())})"


# ── Singleton dùng chung toàn project ─────────────────────────────────────────
_global_attack_store: Optional[AttackStore] = None


def get_attack_store() -> AttackStore:
    global _global_attack_store
    if _global_attack_store is None:
        _global_attack_store = AttackStore()
    return _global_attack_store
