"""Strict, dependency-free policy-as-code loader and validator."""
import json
from pathlib import Path
from typing import Any, Dict, List, Union
from .common import read_regular

REQUIRED_FIELDS = {"id", "effect", "subject", "resource", "action", "min_posture"}
VALID_EFFECTS = {"allow", "deny"}
VALID_POSTURES = {"unknown", "degraded", "compliant"}


def validate_policy(policy: Any) -> List[str]:
    """Validate a single policy dictionary against the Zero Trust schema."""
    errors = []
    if not isinstance(policy, dict):
        return ["policy must be an object"]

    missing = REQUIRED_FIELDS - set(policy.keys())
    if missing:
        errors.append("missing: " + ",".join(sorted(missing)))

    if policy.get("effect") not in VALID_EFFECTS:
        errors.append("effect must be allow or deny")

    if policy.get("min_posture") not in VALID_POSTURES:
        errors.append("min_posture is invalid")

    for field in ("id", "subject", "resource", "action"):
        val = policy.get(field)
        if field in policy and (not isinstance(val, str) or not val.strip()):
            errors.append(f"{field} must be a non-empty string")

    return errors


def load(path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Load, parse, and validate policies from a JSON file, rejecting symlinks."""
    content = read_regular(path).decode("utf-8")
    try:
        data = json.loads(content)
    except json.JSONDecodeError as err:
        raise ValueError(f"Invalid JSON in policy file: {err}") from err

    policies = data.get("policies") if isinstance(data, dict) else data
    if not isinstance(policies, list):
        raise ValueError("policy document must contain a policies list")

    errors = []
    for i, item in enumerate(policies):
        for error in validate_policy(item):
            errors.append(f"policies[{i}]: {error}")

    if errors:
        raise ValueError("; ".join(errors))

    return policies
