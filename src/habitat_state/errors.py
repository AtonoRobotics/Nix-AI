class LedgerUnavailable(RuntimeError):
    """An authoritative dependency cannot currently be reached."""


class LedgerCorrupt(RuntimeError):
    """Authoritative bytes contradict their digest or schema."""

class EvidenceNotFound(LedgerCorrupt):
    """A digest-addressed evidence object does not exist."""

class ActivationInvalid(ValueError):
    """An activation request is malformed, stale, or outside its deadline."""
