"""RFC 8785 JSON Canonicalization Scheme (JCS) Implementation."""

import json
from typing import Any


def _canonicalize_value(val: Any) -> Any:
    if isinstance(val, dict):
        # Sort keys lexicographically by UTF-16 code units
        return {k: _canonicalize_value(val[k]) for k in sorted(val.keys())}
    elif isinstance(val, list):
        return [_canonicalize_value(x) for x in val]
    elif isinstance(val, float):
        # Format integer-valued floats without decimal point if whole
        if val.is_integer():
            return int(val)
        return val
    return val


def canonicalize_json(data: dict) -> bytes:
    """Canonicalize a dictionary to RFC 8785 deterministic UTF-8 bytes.

    Separators are (',', ':') with no whitespace, and keys sorted.
    """
    canonical_obj = _canonicalize_value(data)
    json_str = json.dumps(
        canonical_obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return json_str.encode("utf-8")
