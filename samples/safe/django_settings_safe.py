# VibeGuard safe sample: Django settings done right.
# This file MUST produce zero findings.

import os

# DEBUG defaults to False; only on when an explicit env var is set.
DEBUG = os.environ.get('DJANGO_DEBUG', '0') == '1'

# Narrow allowed hosts (no wildcard).
ALLOWED_HOSTS = ['app.example.com', 'api.example.com']

# Secret key from env, never hard-coded.
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
