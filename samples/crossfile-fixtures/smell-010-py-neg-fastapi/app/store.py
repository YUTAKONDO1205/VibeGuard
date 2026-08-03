"""In-memory stand-in for the persistence layer. No authorization happens here."""

from .models import Item, Report, User

_ACTOR = User("ada", "admin")
_ITEMS = [Item("plumbus", "ada", "Plumbus"), Item("gizmo", "bob", "Gizmo")]
_REPORTS = [Report("q1", "ada", "Q1"), Report("q2", "bob", "Q2")]


def common_parameters(skip: int = 0, limit: int = 100):
    """FastAPI's documented non-security dependency. Injected, decides nothing."""
    return {"skip": skip, "limit": limit}


def current_actor():
    return _ACTOR


def list_items():
    return list(_ITEMS)


def load_item(item_id):
    return next(i for i in _ITEMS if i.item_id == item_id)


def list_reports():
    return list(_REPORTS)


def load_report(report_id):
    return next(r for r in _REPORTS if r.report_id == report_id)
