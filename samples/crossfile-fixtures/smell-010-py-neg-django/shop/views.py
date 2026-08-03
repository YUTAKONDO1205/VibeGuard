"""Shop views.

The role comparisons here narrow a queryset by ownership. Whether the caller is
allowed to reach the view at all is decided in `urls.py` (function views) and by
`LoginRequiredMixin` (the class-based view).
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.views.generic import TemplateView

from .models import Order


def order_list(request):
    orders = Order.objects.all()
    if request.user.role != "manager":
        orders = orders.filter(owner=request.user)
    return JsonResponse({"orders": [o.reference for o in orders]})


def order_export(request):
    orders = Order.objects.all()
    if request.user.role != "manager":
        orders = orders.filter(owner=request.user)
    return JsonResponse({"rows": [o.as_row() for o in orders]})


def order_health(request):
    return JsonResponse({"status": "ok"})


class OrderAuditView(LoginRequiredMixin, TemplateView):
    template_name = "shop/audit.html"

    def get_queryset(self):
        entries = Order.objects.audit_trail()
        if self.request.user.role != "manager":
            entries = entries.filter(owner=self.request.user)
        return entries

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["can_reopen"] = self.request.user.role == "manager"
        context["entries"] = self.get_queryset()
        return context
