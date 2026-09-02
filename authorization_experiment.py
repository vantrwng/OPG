"""OpenAPI-validated plans for deterministic object-authorization tests."""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from attack_store import AttackStore


@dataclass(frozen=True)
class AuthorizationExperiment:
    producer_api: str
    target_api: str
    verifier_api: str
    resource_type: str
    selector_field: str
    operation: str
    actor_relationship: str = "same_role_distinct_principals"


class AuthorizationExperimentPlanner:
    """Infer only relationships which are backed by operations in the spec."""

    def __init__(self, operations: List[Dict]):
        self.operations = list(operations or [])
        self.by_id = {op.get("id"): op for op in self.operations if op.get("id")}

    @staticmethod
    def _selectors(operation: Dict) -> List[str]:
        declared = list(operation.get("resource_selectors", []) or [])
        path_fields = re.findall(r"\{([^}]+)\}", str(operation.get("path", "")))
        return list(dict.fromkeys(str(item) for item in declared + path_fields if item))

    @staticmethod
    def _family(operation: Dict) -> str:
        return AttackStore.normalize_resource_type(
            operation.get("resource_type") or operation.get("path") or operation.get("id", "")
        )

    @staticmethod
    def _producer_rank(operation: Dict):
        """Prefer a direct collection POST over relationship/action POSTs."""
        path = str(operation.get("path", ""))
        path_parameters = len(re.findall(r"\{[^}]+\}", path))
        path_segments = len([part for part in path.split("/") if part])
        return path_parameters, path_segments, str(operation.get("id", ""))

    def plan(self) -> List[AuthorizationExperiment]:
        experiments = []
        for target in self.operations:
            method = str(target.get("method", "GET")).upper()
            selectors = self._selectors(target)
            if method not in {"GET", "PATCH", "PUT", "DELETE"} or not selectors:
                continue
            resource_type = self._family(target)
            selector = selectors[-1]
            canonical_selector = AttackStore.normalize_selector(selector, resource_type)

            producers = sorted([
                op for op in self.operations
                if str(op.get("method", "")).upper() == "POST"
                and self._family(op) == resource_type
            ], key=self._producer_rank)
            verifiers = [
                op for op in self.operations
                if str(op.get("method", "")).upper() == "GET"
                and self._family(op) == resource_type
                and any(
                    AttackStore.normalize_selector(item, resource_type) == canonical_selector
                    for item in self._selectors(op)
                )
            ]
            if not producers or not verifiers:
                continue
            experiments.append(AuthorizationExperiment(
                producer_api=str(producers[0]["id"]),
                target_api=str(target["id"]),
                verifier_api=str(verifiers[0]["id"]),
                resource_type=resource_type,
                selector_field=selector,
                operation=method,
            ))
        return experiments

    def validate(self, experiment: AuthorizationExperiment) -> bool:
        producer = self.by_id.get(experiment.producer_api)
        target = self.by_id.get(experiment.target_api)
        verifier = self.by_id.get(experiment.verifier_api)
        if not producer or not target or not verifier:
            return False
        if str(producer.get("method", "")).upper() != "POST":
            return False
        if str(target.get("method", "")).upper() != experiment.operation:
            return False
        if str(verifier.get("method", "")).upper() != "GET":
            return False
        canonical = AttackStore.normalize_selector(
            experiment.selector_field, experiment.resource_type
        )
        return all(self._family(op) == experiment.resource_type for op in (producer, target, verifier)) \
            and any(
                AttackStore.normalize_selector(item, experiment.resource_type) == canonical
                for item in self._selectors(target)
            ) \
            and any(
                AttackStore.normalize_selector(item, experiment.resource_type) == canonical
                for item in self._selectors(verifier)
            )

    def for_target(self, api_id: str) -> Optional[AuthorizationExperiment]:
        return next((item for item in self.plan() if item.target_api == api_id), None)
