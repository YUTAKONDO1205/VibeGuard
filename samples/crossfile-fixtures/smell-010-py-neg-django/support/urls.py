"""Support URLconf. The same two mechanisms as `shop/urls.py`.

Two applications carry each mechanism so that removing one of them in a copy of
this fixture yields four sites across two files, clearing MIN_SITES and
MIN_FILES on its own. A negative condition removed in a fixture that then stays
silent for a threshold reason would have pinned nothing.
"""

from django.contrib.auth.decorators import login_required, permission_required
from django.urls import path

from . import views

app_name = "support"

urlpatterns = [
    path("tickets/", login_required(views.ticket_list), name="ticket-list"),
    path(
        "tickets/close/",
        permission_required("support.close_ticket")(views.ticket_close),
        name="ticket-close",
    ),
    path("tickets/audit/", views.TicketAuditView.as_view(), name="ticket-audit"),
]
