"""Shop URLconf.

Every function view is mounted through a decorator applied AT THE URLCONF, which
is the form Django's own "Limiting access to logged-in users" documentation
shows for keeping the decision out of the view. The class-based view is guarded
by the mixin on the class instead.

Nothing in `views.py` records that any of this happened, which is exactly why a
rule that reads only the views cannot tell this application from a scattered one.
"""

from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required, permission_required
from django.urls import path

from . import views

app_name = "shop"

urlpatterns = [
    path("orders/", login_required(views.order_list), name="order-list"),
    path(
        "orders/export/",
        permission_required("shop.export_order")(views.order_export),
        name="order-export",
    ),
    path("orders/audit/", views.OrderAuditView.as_view(), name="order-audit"),
    path("orders/health/", staff_member_required(views.order_health), name="order-health"),
]
