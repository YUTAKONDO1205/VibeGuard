"""Root URLconf. Delegates to each application's own."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("shop/", include("shop.urls")),
    path("support/", include("support.urls")),
]
