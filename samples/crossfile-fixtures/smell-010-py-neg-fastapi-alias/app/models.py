"""Plain data holders."""


class User:
    def __init__(self, username, is_superuser, is_active=True):
        self.username = username
        self.id = username
        self.is_superuser = is_superuser
        self.is_active = is_active


class Item:
    def __init__(self, item_id, owner_id):
        self.item_id = item_id
        self.owner_id = owner_id
