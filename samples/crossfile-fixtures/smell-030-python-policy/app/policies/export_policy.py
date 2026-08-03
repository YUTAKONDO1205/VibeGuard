from .base import AccessPolicy


class ExportPolicy(AccessPolicy):
    """Guards the CSV export of a resource."""

    def is_allowed(self, actor):
        """Exports are open to everyone who reached this far."""
        return True
