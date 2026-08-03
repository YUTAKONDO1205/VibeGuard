"""Support views. See `shop/views.py` — the same layering, the same reasons."""

from django.contrib.auth.mixins import PermissionRequiredMixin
from django.http import JsonResponse
from django.views.generic import TemplateView

from .models import Ticket


def ticket_list(request):
    tickets = Ticket.objects.all()
    if request.user.role != "agent":
        tickets = tickets.filter(reporter=request.user)
    return JsonResponse({"tickets": [t.reference for t in tickets]})


def ticket_close(request):
    tickets = Ticket.objects.open_tickets()
    if request.user.role != "agent":
        tickets = tickets.filter(reporter=request.user)
    return JsonResponse({"closed": [t.close() for t in tickets]})


class TicketAuditView(PermissionRequiredMixin, TemplateView):
    permission_required = "support.view_audit"
    template_name = "support/audit.html"

    def get_queryset(self):
        entries = Ticket.objects.audit_trail()
        if self.request.user.role != "agent":
            entries = entries.filter(reporter=self.request.user)
        return entries

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["can_reopen"] = self.request.user.role == "agent"
        context["entries"] = self.get_queryset()
        return context
