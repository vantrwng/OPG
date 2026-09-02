"""Generic OpenAPI-backed resource lifecycle provisioning for experiments."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from attack_store import AttackStore
from reference_engine import ProvenanceChain, ProvenanceLevel
from response_outcome import result_succeeded


@dataclass
class ProvisioningResult:
    status: str
    reason: str = ""
    resource_id: Any = None
    selector_field: str = ""
    resource_type: str = ""
    producer_api: str = ""
    verifier_api: str = ""
    create_result: Dict[str, Any] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return self.status == "provisioned" and self.resource_id not in (None, "")


class GenericResourceProvisioner:
    def __init__(self, operations, planner, executor, store: AttackStore):
        self.operations = {item.get("id"): item for item in (operations or [])}
        self.planner = planner
        self.executor = executor
        self.store = store

    def provision(self, target: Mapping[str, Any], owner_state) -> ProvisioningResult:
        experiment = self.planner.for_target(str(target.get("id", "")))
        if experiment is None or not self.planner.validate(experiment):
            return ProvisioningResult(
                "provisioning_failed",
                "No OpenAPI create/read lifecycle matches the target selector",
            )
        producer = self.operations.get(experiment.producer_api)
        if not producer:
            return ProvisioningResult(
                "provisioning_failed", "The inferred producer operation is unavailable",
            )
        selector_meta = self._selector_meta(
            producer, experiment.selector_field, experiment.resource_type
        )
        if not selector_meta:
            return ProvisioningResult(
                "provisioning_failed",
                "Producer has no declared selector in its successful post-condition",
                selector_field=experiment.selector_field,
                resource_type=experiment.resource_type,
                producer_api=experiment.producer_api,
                verifier_api=experiment.verifier_api,
            )
        try:
            created = self.executor.execute_request(
                producer, owner_state, payload_source_override="RESOURCE_PROVISIONER",
                allow_repair=True, allow_auth_recovery=True,
            )
        except Exception as exc:
            return ProvisioningResult(
                "provisioning_failed", f"{type(exc).__name__}: {exc}",
                selector_field=experiment.selector_field,
                resource_type=experiment.resource_type,
                producer_api=experiment.producer_api,
                verifier_api=experiment.verifier_api,
            )
        if not result_succeeded(created) or created.get("schema_valid") is False:
            return ProvisioningResult(
                "provisioning_failed",
                f"Create operation failed verification: HTTP {created.get('status', 0)} "
                f"{created.get('outcome_reason', '')}".strip(),
                selector_field=experiment.selector_field,
                resource_type=experiment.resource_type,
                producer_api=experiment.producer_api,
                verifier_api=experiment.verifier_api,
                create_result=created,
            )
        resource_id = self._capture_selector(created, selector_meta)
        if resource_id in (None, "") or isinstance(resource_id, (dict, list)):
            return ProvisioningResult(
                "provisioning_failed",
                "Create succeeded but its declared selector could not be captured",
                selector_field=experiment.selector_field,
                resource_type=experiment.resource_type,
                producer_api=experiment.producer_api,
                verifier_api=experiment.verifier_api,
                create_result=created,
            )
        chain = ProvenanceChain.single(
            "create_response" if not selector_meta.get("_request_passthrough") else "create_request_postcondition",
            ProvenanceLevel.AUTHORITATIVE,
            0.95,
            relation=experiment.resource_type,
            actor_id=str(owner_state.get("actor_id", "default")),
            operation_id=experiment.producer_api,
        )
        self.store.record(
            experiment.producer_api,
            experiment.selector_field,
            resource_id,
            endpoint=created.get("url", producer.get("path", "")),
            owner_actor_id=owner_state.get("actor_id", "default"),
            owner_role=owner_state.get("actor_role", ""),
            resource_type=experiment.resource_type,
            provenance="AUTHORITATIVE",
            provenance_chain=chain,
            producer_method="POST",
            schema=selector_meta,
            user_context={"actor_id": owner_state.get("actor_id", "default")},
        )
        return ProvisioningResult(
            "provisioned",
            resource_id=resource_id,
            selector_field=experiment.selector_field,
            resource_type=experiment.resource_type,
            producer_api=experiment.producer_api,
            verifier_api=experiment.verifier_api,
            create_result=created,
        )

    @staticmethod
    def _selector_meta(operation, selector, resource_type) -> Optional[Dict[str, Any]]:
        canonical = AttackStore.normalize_selector(selector, resource_type)
        # The parser normally exposes post-conditions through ``outputs``.
        # Accept the explicit request-postcondition names as well so callers
        # using an already-normalized OpenAPI operation retain the same rules.
        collections = [
            (operation.get("outputs", {}) or {}, False),
            (operation.get("postconditions", {}) or {}, True),
            (operation.get("request_postconditions", {}) or {}, True),
        ]
        for fields, request_passthrough in collections:
            for field, raw_meta in fields.items():
                meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}
                if request_passthrough:
                    meta.setdefault("_request_passthrough", True)
                names = (field, meta.get("original", ""), meta.get("contextual_name", ""))
                if any(
                    AttackStore.normalize_selector(name, resource_type) == canonical
                    for name in names if name
                ):
                    return meta
        return None

    @classmethod
    def _capture_selector(cls, created, selector_meta):
        if selector_meta.get("_request_passthrough"):
            source = created.get("sent_payload", {})
        else:
            source = created.get("raw_response")
        path = selector_meta.get("json_path") or selector_meta.get("original")
        return cls._value_at_path(source, path)

    @staticmethod
    def _value_at_path(value, path):
        parts = [part for part in re.split(r"\.|\[\]", str(path or "")) if part]
        current = value
        for part in parts:
            if isinstance(current, list):
                current = current[0] if current else None
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current
