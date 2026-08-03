"""In-memory stand-in for the persistence layer. No authorization happens here."""


class Order:
    def __init__(self, order_id, reference):
        self.order_id = order_id
        self.reference = reference

    def cancel(self):
        self.reference = ""


class Summary:
    def __init__(self, summary):
        self.summary = summary


_ORDERS = [Order(1, "ORD-1"), Order(2, "ORD-2")]
_REPORTS = [Summary("two orders open")]


def list_orders():
    return list(_ORDERS)


def load_order(order_id):
    return next(o for o in _ORDERS if o.order_id == order_id)


def list_reports():
    return list(_REPORTS)
