"""SafeStack Zero Trust Policy Decision Engine."""
from datetime import datetime, timezone
from typing import Any, Dict
from .store import Store

POSTURE_LEVELS = {
    "unknown": 0,
    "degraded": 1,
    "compliant": 2,
}


class Decision:
    """Represents an access evaluation decision outcome."""

    def __init__(
        self,
        allowed: bool,
        reason: str,
        device_id: str,
        subject: str,
        resource: str,
        action: str,
    ):
        self.allowed = allowed
        self.reason = reason
        self.device_id = device_id
        self.subject = subject
        self.resource = resource
        self.action = action

    def as_dict(self) -> Dict[str, Any]:
        """Convert decision to a serializable dictionary."""
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "device_id": self.device_id,
            "subject": self.subject,
            "resource": self.resource,
            "action": self.action,
        }

    def __repr__(self) -> str:
        status = "ALLOW" if self.allowed else "DENY"
        return f"<Decision {status} reason='{self.reason}' subject='{self.subject}' resource='{self.resource}'>"


def evaluate(
    store: Store,
    device_id: str,
    subject: str,
    resource: str,
    action: str,
) -> Decision:
    """Evaluate access request against device posture and stored policies with default-deny semantics."""
    if not isinstance(device_id, str) or not device_id.strip():
        raise ValueError("device_id must be a non-empty string")
    if not isinstance(subject, str) or not subject.strip():
        raise ValueError("subject must be a non-empty string")
    if not isinstance(resource, str) or not resource.strip():
        raise ValueError("resource must be a non-empty string")
    if not isinstance(action, str) or not action.strip():
        raise ValueError("action must be a non-empty string")

    device = store.device(device_id)
    if not device:
        return Decision(False, "device_not_registered", device_id, subject, resource, action)

    policies = store.policies(subject, resource, action)
    if not policies:
        result = Decision(False, "no_matching_policy", device_id, subject, resource, action)
    else:
        result = Decision(False, "default_deny", device_id, subject, resource, action)
        for p in policies:
            dev_posture = POSTURE_LEVELS.get(device["posture"], 0)
            req_posture = POSTURE_LEVELS.get(p["min_posture"], 99)
            if dev_posture < req_posture:
                result = Decision(False, "device_posture_below_policy", device_id, subject, resource, action)
                break
            if p["effect"] == "deny":
                result = Decision(False, "explicit_deny", device_id, subject, resource, action)
                break
            if p["effect"] == "allow":
                result = Decision(True, "policy_allow", device_id, subject, resource, action)
                break

    now = datetime.now(timezone.utc).isoformat()
    store.decision((
        device_id,
        subject,
        resource,
        action,
        int(result.allowed),
        result.reason,
        now,
    ))
    return result
