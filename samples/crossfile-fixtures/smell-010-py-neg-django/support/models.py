"""Models. No authorization happens here."""

from django.db import models


class Ticket(models.Model):
    reference = models.CharField(max_length=32)
    reporter = models.ForeignKey("auth.User", on_delete=models.CASCADE)

    def close(self):
        return self.reference
