"""A stand-in database handle. Deliberately NOT named `session`.

`session` is an authentication guard word in `authz-lexicon`, so a dependency
called `get_session` silences a handler through `guardNames`. Naming this
`open_db` keeps `SessionDep` an honest control: it must be a dependency alias
that does NOT silence, which it cannot be if its own factory reads as a guard.
"""

from app.models import Item, User

_USERS = {"tok-admin": User("ada", True), "tok-plain": User("bob", False)}
_ITEMS = [Item("plumbus", "ada"), Item("gizmo", "bob")]


class Session:
    def lookup(self, token):
        return _USERS.get(token)

    def all_items(self, skip):
        return _ITEMS[skip:]

    def items_owned_by(self, owner_id, skip):
        return [i for i in _ITEMS if i.owner_id == owner_id][skip:]

    def get_item(self, item_id):
        return next((i for i in _ITEMS if i.item_id == item_id), None)

    def all_users(self, skip):
        return list(_USERS.values())[skip:]

    def get_user(self, username):
        return next((u for u in _USERS.values() if u.username == username), None)


def open_db():
    return Session()
