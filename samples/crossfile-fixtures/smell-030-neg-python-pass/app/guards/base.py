class PermissionGuard:
    """Decides whether an actor holds a named permission."""

    def __init__(self, needed):
        self.needed = needed

    def check_permission(self, actor):
        if actor is None:
            return False
        return self.needed in actor.permissions
