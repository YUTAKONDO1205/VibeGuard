"""Models. No authorization happens here."""

from django.db import models


class Order(models.Model):
    reference = models.CharField(max_length=32)
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)

    def as_row(self):
        return [self.reference, self.owner_id]
