# VibeGuard sample: Django settings.py with classic AI-scaffold defaults.

import os

# VG-FW-001 — DEBUG left on in a settings module.
DEBUG = True

ALLOWED_HOSTS = ['*']

SECRET_KEY = 'django-insecure-replace-me'


# VG-AUTH-005 — disabling CSRF protection on a state-changing view.
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def webhook(request):
    # accepts POST without CSRF check
    return None
