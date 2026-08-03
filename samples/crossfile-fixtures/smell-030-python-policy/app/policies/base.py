class AccessPolicy:
    """Decides whether an actor may act on one resource."""

    def __init__(self, resource):
        self.resource = resource

    def is_allowed(self, actor):
        """Owners always may; everyone else needs the reader role."""
        if actor is None:
            return False
        if self.resource.owner_id == actor.id:
            return True
        return "reader" in actor.roles
