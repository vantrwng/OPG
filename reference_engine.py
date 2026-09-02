"""Dataset-neutral reference discovery, value provenance, and request mutation."""

from __future__ import annotations

import copy
import math
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


class ProvenanceLevel(IntEnum):
    GUESSED = 0
    DERIVED = 1
    OBSERVED = 2
    AUTHORITATIVE = 3

    @classmethod
    def parse(cls, value: Any) -> "ProvenanceLevel":
        if isinstance(value, cls):
            return value
        normalized = str(value or "").strip().upper()
        legacy = {
            "CREATED_RESPONSE": cls.AUTHORITATIVE,
            "ACTOR_BOOTSTRAP": cls.AUTHORITATIVE,
            "OBSERVED_RESPONSE": cls.OBSERVED,
            "OBSERVED_REQUEST": cls.OBSERVED,
            "HEURISTIC": cls.DERIVED,
            "LLM": cls.GUESSED,
        }
        return legacy.get(normalized, cls.__members__.get(normalized, cls.GUESSED))


@dataclass(frozen=True)
class ProvenanceEvidence:
    source: str
    level: ProvenanceLevel
    confidence: float = 0.5
    relation: str = ""
    actor_id: str = ""
    operation_id: str = ""


@dataclass(frozen=True)
class ProvenanceChain:
    evidence: Tuple[ProvenanceEvidence, ...] = ()

    @classmethod
    def single(
        cls, source: str, level: Any, confidence: float = 0.5, **context: Any
    ) -> "ProvenanceChain":
        return cls((ProvenanceEvidence(
            source=source,
            level=ProvenanceLevel.parse(level),
            confidence=max(0.0, min(float(confidence), 1.0)),
            relation=str(context.get("relation", "")),
            actor_id=str(context.get("actor_id", "")),
            operation_id=str(context.get("operation_id", "")),
        ),))

    def extend(self, evidence: ProvenanceEvidence) -> "ProvenanceChain":
        if evidence in self.evidence:
            return self
        return ProvenanceChain(self.evidence + (evidence,))

    @property
    def level(self) -> ProvenanceLevel:
        if not self.evidence:
            return ProvenanceLevel.GUESSED
        strongest = max(item.level for item in self.evidence)
        independent_observations = {
            (item.source, item.operation_id, item.relation)
            for item in self.evidence
            if item.level >= ProvenanceLevel.OBSERVED
        }
        # Corroborated request/response or create/read evidence is stronger than
        # either observation alone, irrespective of domain naming.
        if strongest == ProvenanceLevel.OBSERVED and len(independent_observations) >= 2:
            return ProvenanceLevel.AUTHORITATIVE
        return strongest

    @property
    def confidence(self) -> float:
        if not self.evidence:
            return 0.0
        residual = 1.0
        for item in self.evidence:
            residual *= 1.0 - max(0.0, min(item.confidence, 1.0))
        confidence = 1.0 - residual
        if self.level == ProvenanceLevel.AUTHORITATIVE:
            confidence = max(confidence, 0.85)
        return min(confidence, 1.0)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.name.lower(),
            "confidence": round(self.confidence, 4),
            "evidence": [
                {
                    "source": item.source,
                    "level": item.level.name.lower(),
                    "confidence": item.confidence,
                    "relation": item.relation,
                    "actor_id": item.actor_id,
                    "operation_id": item.operation_id,
                }
                for item in self.evidence
            ],
        }


@dataclass(frozen=True)
class ObservedValue:
    value: Any
    schema: Mapping[str, Any]
    location: str
    field_path: str
    provenance: ProvenanceChain
    operation_id: str = ""
    actor_id: str = ""
    relationship: str = ""
    observed_at: float = field(default_factory=time.time)


@dataclass
class ReferenceCandidate:
    location: str
    field_path: str
    schema: Dict[str, Any]
    original_value: Any
    candidate_values: List[ObservedValue] = field(default_factory=list)
    provenance: ProvenanceChain = field(default_factory=ProvenanceChain)
    confidence: float = 0.0
    parameter_name: str = ""
    normalized_field: str = ""


def _tokens(value: Any) -> set[str]:
    expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(value or ""))
    return {part.casefold() for part in re.split(r"[^A-Za-z0-9]+", expanded) if part}


def _schema_type(schema: Mapping[str, Any]) -> str:
    value = str(schema.get("type", "") or "").casefold()
    if value:
        return value
    return "unknown"


def schema_compatible(value: Any, schema: Mapping[str, Any]) -> bool:
    if value is None:
        return False
    expected = _schema_type(schema)
    if expected == "string" and not isinstance(value, str):
        return False
    if expected == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
        return False
    if expected == "number" and (not isinstance(value, (int, float)) or isinstance(value, bool)):
        return False
    if expected == "boolean" and not isinstance(value, bool):
        return False
    if expected == "array" and not isinstance(value, (list, tuple)):
        return False
    if expected == "object" and not isinstance(value, dict):
        return False
    enum = schema.get("enum") or []
    if enum and value not in enum:
        return False
    if isinstance(value, str):
        if schema.get("minLength") is not None and len(value) < int(schema["minLength"]):
            return False
        if schema.get("maxLength") is not None and len(value) > int(schema["maxLength"]):
            return False
        pattern = schema.get("pattern")
        if pattern:
            try:
                if re.fullmatch(str(pattern), value) is None:
                    return False
            except re.error:
                return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if schema.get("minimum") is not None and value < schema["minimum"]:
            return False
        if schema.get("maximum") is not None and value > schema["maximum"]:
            return False
        if schema.get("exclusiveMinimum") is not None and value <= schema["exclusiveMinimum"]:
            return False
        if schema.get("exclusiveMaximum") is not None and value >= schema["exclusiveMaximum"]:
            return False
    return True


class ObservedValuePool:
    """Session-scoped values with evidence retained across request/response hops."""

    def __init__(self) -> None:
        self._values: List[ObservedValue] = []

    def observe(self, observation: ObservedValue) -> None:
        for index, existing in enumerate(self._values):
            same_identity = (
                existing.value == observation.value
                and existing.field_path == observation.field_path
                and existing.actor_id == observation.actor_id
            )
            if not same_identity:
                continue
            chain = existing.provenance
            for evidence in observation.provenance.evidence:
                chain = chain.extend(evidence)
            self._values[index] = ObservedValue(
                value=existing.value,
                schema=existing.schema or observation.schema,
                location=existing.location,
                field_path=existing.field_path,
                provenance=chain,
                operation_id=existing.operation_id or observation.operation_id,
                actor_id=existing.actor_id or observation.actor_id,
                relationship=existing.relationship or observation.relationship,
                observed_at=max(existing.observed_at, observation.observed_at),
            )
            return
        self._values.append(observation)

    def candidates_for(
        self,
        schema: Mapping[str, Any],
        field_path: str,
        original_value: Any,
        actor_id: str = "",
        relationship: str = "",
        limit: int = 5,
    ) -> List[ObservedValue]:
        target_tokens = _tokens(field_path)
        target_format = str(schema.get("format", "") or "").casefold()
        scored = []
        for item in self._values:
            if item.value == original_value or not schema_compatible(item.value, schema):
                continue
            score = item.provenance.confidence
            item_format = str(item.schema.get("format", "") or "").casefold()
            if target_format and target_format == item_format:
                score += 0.35
            if _schema_type(schema) == _schema_type(item.schema):
                score += 0.15
            overlap = target_tokens & _tokens(item.field_path)
            score += min(0.3, 0.1 * len(overlap))
            if relationship and relationship == item.relationship:
                score += 0.35
            if actor_id and item.actor_id and actor_id != item.actor_id:
                score += 0.1
            scored.append((score, item.observed_at, item))
        scored.sort(key=lambda entry: (entry[0], entry[1]), reverse=True)
        return [entry[2] for entry in scored[:limit]]

    def all(self) -> List[ObservedValue]:
        return list(self._values)


class ReferenceDiscovery:
    IDENTIFIER_FORMATS = {"uuid", "uri", "url", "email", "hostname", "ipv4", "ipv6"}
    IDENTIFIER_HINTS = {"id", "uuid", "guid", "ref", "reference", "key", "slug", "code"}

    def __init__(self, pool: ObservedValuePool):
        self.pool = pool

    def discover(
        self,
        operation: Mapping[str, Any],
        request_values: Mapping[str, Any],
        actor_id: str = "",
    ) -> List[ReferenceCandidate]:
        result = []
        for normalized, raw_schema in (operation.get("inputs", {}) or {}).items():
            schema = dict(raw_schema) if isinstance(raw_schema, Mapping) else {}
            location = str(schema.get("in", "body")).casefold()
            parameter_name = str(schema.get("original", normalized))
            field_path = str(schema.get("json_path") or parameter_name)
            original = self._read_value(request_values, location, parameter_name, field_path)
            candidates = self.pool.candidates_for(
                schema, field_path, original, actor_id=actor_id,
                relationship=str(operation.get("resource_type", "")),
            )
            confidence = self._confidence(
                location, field_path, schema, original, bool(candidates)
            )
            if confidence < 0.45:
                continue
            provenance = ProvenanceChain.single(
                "openapi_request", ProvenanceLevel.DERIVED, confidence,
                relation=location, operation_id=str(operation.get("id", "")),
                actor_id=actor_id,
            )
            result.append(ReferenceCandidate(
                location=location,
                field_path=field_path,
                schema=schema,
                original_value=original,
                candidate_values=candidates,
                provenance=provenance,
                confidence=confidence,
                parameter_name=parameter_name,
                normalized_field=str(normalized),
            ))
        return sorted(result, key=lambda item: item.confidence, reverse=True)

    @classmethod
    def _confidence(
        cls, location: str, field_path: str, schema: Mapping[str, Any],
        original: Any, has_candidates: bool,
    ) -> float:
        score = 0.0
        scalar = _schema_type(schema) in {"string", "integer", "number", "unknown"}
        if location == "path" and scalar:
            score += 0.55
        if str(schema.get("format", "")).casefold() in cls.IDENTIFIER_FORMATS:
            score += 0.35
        if _tokens(field_path) & cls.IDENTIFIER_HINTS:
            score += 0.25
        if original not in (None, "") and scalar:
            score += 0.1
        if has_candidates:
            score += 0.35
        if schema.get("enum"):
            score -= 0.2
        return max(0.0, min(score, 1.0))

    @staticmethod
    def _read_value(values: Mapping[str, Any], location: str, name: str, path: str) -> Any:
        if location != "body":
            return values.get(name, values.get(path))
        current: Any = values
        for part in [part for part in re.split(r"\.|\[\]", path) if part]:
            if isinstance(current, list):
                current = current[0] if current else None
            if not isinstance(current, Mapping):
                return values.get(name)
            current = current.get(part)
        return current


class RequestTransformer:
    @staticmethod
    def transform(
        operation: Mapping[str, Any], payload: Mapping[str, Any],
        candidate: ReferenceCandidate, replacement: Any,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        if replacement == candidate.original_value or not schema_compatible(replacement, candidate.schema):
            raise ValueError("replacement must be schema-compatible and differ from baseline")
        node = copy.deepcopy(dict(operation))
        changed = copy.deepcopy(dict(payload or {}))
        if candidate.location == "path":
            placeholder = "{" + candidate.parameter_name + "}"
            original_path = str(node.get("path", ""))
            node["path"] = original_path.replace(placeholder, str(replacement), 1)
            if node["path"] == original_path:
                raise ValueError(f"path parameter {candidate.parameter_name!r} was not found")
            changed[candidate.parameter_name] = replacement
        elif candidate.location in {"query", "header", "cookie"}:
            changed[candidate.parameter_name] = replacement
        elif candidate.location == "body":
            RequestTransformer._set_json_path(changed, candidate.field_path, replacement)
        else:
            raise ValueError(f"unsupported reference location: {candidate.location}")
        return node, changed

    @staticmethod
    def _set_json_path(document: Dict[str, Any], path: str, value: Any) -> None:
        parts = [part for part in re.split(r"\.|\[\]", str(path or "")) if part]
        if not parts:
            raise ValueError("body reference has no JSON path")
        current: Any = document
        for part in parts[:-1]:
            if isinstance(current, list):
                if not current:
                    current.append({})
                current = current[0]
            child = current.get(part) if isinstance(current, dict) else None
            if child is None:
                child = [] if "[]" in path and part == parts[-2] else {}
                current[part] = child
            current = child
        if isinstance(current, list):
            if not current:
                current.append({})
            current = current[0]
        current[parts[-1]] = value


class ObservableMutator:
    """Create the smallest schema-valid value that differs from a baseline."""

    @classmethod
    def mutate(cls, value: Any, schema: Mapping[str, Any]) -> Any:
        enum = list(schema.get("enum") or [])
        if enum:
            alternative = next((item for item in enum if item != value), None)
            if alternative is None:
                raise ValueError("enum has no alternative value")
            return alternative
        kind = _schema_type(schema)
        if kind == "boolean" or isinstance(value, bool):
            return not bool(value)
        if kind in {"integer", "number"} or (
            isinstance(value, (int, float)) and not isinstance(value, bool)
        ):
            return cls._mutate_number(value, schema, integer=kind == "integer" or isinstance(value, int))
        if kind == "array" or isinstance(value, list):
            result = copy.deepcopy(value if isinstance(value, list) else [])
            item_schema = schema.get("items") if isinstance(schema.get("items"), Mapping) else {}
            if result:
                result[0] = cls.mutate(result[0], item_schema)
            else:
                result.append(cls._seed(item_schema))
            return result
        if kind == "object" or isinstance(value, dict):
            result = copy.deepcopy(value if isinstance(value, dict) else {})
            properties = schema.get("properties") if isinstance(schema.get("properties"), Mapping) else {}
            for key, child_schema in properties.items():
                if key in result:
                    result[key] = cls.mutate(result[key], child_schema or {})
                    return result
            key = next(iter(properties), "value")
            result[key] = cls._seed(properties.get(key, {}) if properties else {})
            return result
        return cls._mutate_string(str(value or ""), schema)

    @staticmethod
    def _mutate_number(value: Any, schema: Mapping[str, Any], integer: bool) -> Any:
        baseline = value if isinstance(value, (int, float)) else 0
        step = schema.get("multipleOf") or 1
        candidates = [baseline + step, baseline - step]
        for candidate in candidates:
            if integer:
                candidate = int(candidate)
            if candidate != value and schema_compatible(candidate, {**schema, "type": "integer" if integer else "number"}):
                return candidate
        minimum = schema.get("minimum", schema.get("exclusiveMinimum", 0))
        candidate = minimum + (step if schema.get("exclusiveMinimum") is not None else 0)
        if integer:
            candidate = int(math.ceil(candidate))
        if candidate != value and schema_compatible(candidate, schema):
            return candidate
        raise ValueError("numeric constraints leave no alternative value")

    @staticmethod
    def _mutate_string(value: str, schema: Mapping[str, Any]) -> str:
        suffix = uuid.uuid4().hex[:8]
        maximum = int(schema.get("maxLength", max(len(value) + 9, 16)))
        minimum = int(schema.get("minLength", 1))
        candidate = f"{value}-{suffix}" if value else suffix
        candidate = candidate[:maximum]
        if len(candidate) < minimum:
            candidate += "x" * (minimum - len(candidate))
        pattern = schema.get("pattern")
        if pattern:
            # Preserve a matching baseline and alter one unconstrained-looking
            # character. Complex regex generation is deliberately not guessed.
            for index, char in enumerate(value):
                replacement = "b" if char != "b" else "c"
                trial = value[:index] + replacement + value[index + 1:]
                try:
                    if trial != value and re.fullmatch(str(pattern), trial):
                        return trial
                except re.error as exc:
                    raise ValueError(f"invalid OpenAPI pattern: {exc}") from exc
            raise ValueError("pattern constraints leave no safely generated alternative")
        if candidate == value:
            raise ValueError("string constraints leave no alternative value")
        return candidate

    @classmethod
    def _seed(cls, schema: Mapping[str, Any]) -> Any:
        kind = _schema_type(schema)
        if schema.get("enum"):
            return schema["enum"][0]
        if kind == "boolean":
            return True
        if kind in {"integer", "number"}:
            return schema.get("minimum", 0)
        if kind == "array":
            return []
        if kind == "object":
            return {}
        return cls._mutate_string("", schema)

    @classmethod
    def mutate_request(
        cls,
        operation: Mapping[str, Any],
        payload: Mapping[str, Any],
        excluded_paths: Sequence[str] = (),
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Mutate one declared writable body field and describe the delta."""
        changed = copy.deepcopy(dict(payload or {}))
        excluded = {str(item) for item in excluded_paths}
        failures = []
        for normalized, raw_schema in (operation.get("inputs", {}) or {}).items():
            schema = dict(raw_schema) if isinstance(raw_schema, Mapping) else {}
            if str(schema.get("in", "body")).casefold() != "body" or schema.get("readOnly"):
                continue
            name = str(schema.get("original", normalized))
            path = str(schema.get("json_path") or name)
            if path in excluded or name in excluded:
                continue
            before = ReferenceDiscovery._read_value(changed, "body", name, path)
            if before is None:
                continue
            try:
                after = cls.mutate(before, schema)
            except ValueError as exc:
                failures.append(f"{path}: {exc}")
                continue
            if after == before:
                continue
            RequestTransformer._set_json_path(changed, path, after)
            return changed, {
                "location": "body", "field_path": path,
                "before": before, "after": after,
            }
        reason = "; ".join(failures) or "no mutable declared body value was present"
        raise ValueError(reason)


def iter_scalar_observations(value: Any, path: str = "") -> Iterable[Tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from iter_scalar_observations(child, child_path)
    elif isinstance(value, list):
        for child in value:
            yield from iter_scalar_observations(child, f"{path}[]")
    elif value is not None:
        yield path, value
