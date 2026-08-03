"""Plain data holders."""


class User:
    def __init__(self, username, role, disabled=False):
        self.username = username
        self.role = role
        self.disabled = disabled
        self.id = username


class Item:
    def __init__(self, item_id, owner_id, name):
        self.item_id = item_id
        self.owner_id = owner_id
        self.name = name

    def rename(self, name):
        self.name = name


class Report:
    def __init__(self, report_id, owner_id, title):
        self.report_id = report_id
        self.owner_id = owner_id
        self.title = title

    def retire(self):
        self.title = ""
