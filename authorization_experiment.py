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
    def _families(operation: Dict) -> List[str]:
        """Return plausible resource families without treating actions as nouns."""
        explicit = operation.get("resource_type")
        path = str(operation.get("path", ""))
        segments = [
            part for part in path.split("/")
            if part and not re.fullmatch(r"v\d+", part, re.I)
            and not re.fullmatch(r"\{[^}]+\}", part)
        ]
        action_segments = {
            "login", "signin", "signup", "register", "registration", "logout",
            "refresh", "password", "email", "verify", "reset", "activate",
        }
        path_candidates = list(segments)
        if path_candidates and path_candidates[-1].casefold() in action_segments:
            path_candidates.pop()

        selectors = AuthorizationExperimentPlanner._selectors(operation)
        selector_candidates = []
        for selector in selectors:
            expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", selector)
            tokens = [part for part in re.split(r"[^a-z0-9]+", expanded.casefold()) if part]
            if not tokens:
                continue
            if tokens[-1] in {"id", "key", "uuid", "title", "name"} and len(tokens) > 1:
                selector_candidates.append(tokens[0])
            elif tokens[-1] in {"username", "userid"}:
                selector_candidates.append("user")

        raw_candidates = [explicit, *selector_candidates, *reversed(path_candidates), path]
        families = []
        for candidate in raw_candidates:
            if not candidate:
                continue
            normalized = AttackStore.normalize_resource_type(candidate)
            if normalized not in families:
                families.append(normalized)
        return families or [AttackStore.normalize_resource_type(operation.get("id", ""))]

    @staticmethod
    def _family(operation: Dict) -> str:
        return AuthorizationExperimentPlanner._families(operation)[0]

    @staticmethod
    def _producer_rank(operation: Dict):
        """Prefer a direct collection POST over relationship/action POSTs."""
        path = str(operation.get("path", ""))
        path_parameters = len(re.findall(r"\{[^}]+\}", path))
        path_segments = len([part for part in path.split("/") if part])
        return path_parameters, path_segments, str(operation.get("id", ""))

    @staticmethod
    def _is_creation_producer(operation: Dict) -> bool:
        if str(operation.get("method", "")).upper() != "POST":
            return False
        text = " ".join((
            str(operation.get("id", "")), str(operation.get("path", "")),
            str(operation.get("summary", "")), str(operation.get("description", "")),
        ))
        return not re.search(
            r"login|log[_-]?in|signin|sign[_-]?in|logout|refresh|authenticate|token",
            text, re.I,
        )

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
                if self._is_creation_producer(op)
                and resource_type in self._families(op)
            ], key=self._producer_rank)
            verifiers = [
                op for op in self.operations
                if str(op.get("method", "")).upper() == "GET"
                and resource_type in self._families(op)
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
        return all(experiment.resource_type in self._families(op) for op in (producer, target, verifier)) \
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
