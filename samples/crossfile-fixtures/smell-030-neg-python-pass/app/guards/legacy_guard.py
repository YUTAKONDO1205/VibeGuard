from .base import PermissionGuard


class LegacyGuard(PermissionGuard):
    """Left over from the v1 API. Nothing has been implemented here."""

    def check_permission(self, actor):
        pass
