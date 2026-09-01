"""Small, domain-neutral helpers for interpreting OpenAPI field metadata."""

import re
from typing import Any, Mapping, Optional


_REFERENCE_TOKENS = {"id", "ids", "uuid", "uuids", "guid", "guids", "ref", "refs", "reference", "references", "key", "keys"}


def normalize_field_name(name: Any) -> str:
    return re.sub(r"[_\-.\s]", "", str(name or "")).lower()


def _field_tokens(name: Any) -> list[str]:
    raw = str(name or "").strip()
    # Preserve semantic boundaries from both camelCase/PascalCase and separators.
    expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", raw)
    return [token.lower() for token in re.split(r"[^A-Za-z0-9]+", expanded) if token]


def is_reference_field(field_name: Any, meta: Optional[Mapping[str, Any]] = None) -> bool:
    """Return whether a field structurally looks like an ID/reference.

    The decision uses naming structure rather than endpoint/domain names.  The
    original OpenAPI spelling is especially important because normalized graph
    keys may have already lost the camelCase boundary in ``resourceId``.
    """
    candidates = [field_name]
    if isinstance(meta, Mapping):
        candidates.extend((meta.get("original"), meta.get("contextual_name")))

    for candidate in candidates:
        tokens = _field_tokens(candidate)
        if tokens and tokens[-1] in _REFERENCE_TOKENS:
            return True
    return False


def value_matches_openapi_type(value: Any, meta: Optional[Mapping[str, Any]]) -> bool:
    """Reject obvious scalar/container mismatches while allowing unknown types."""
    if value is None:
        return False
    expected = str((meta or {}).get("type", "")).lower()
    if expected == "array":
        return isinstance(value, (list, tuple))
    if expected == "object":
        return isinstance(value, dict)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "string":
        return not isinstance(value, (dict, list, tuple))
    return True
