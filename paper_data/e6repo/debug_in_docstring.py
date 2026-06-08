# E6 fixture — Django DEBUG flag.
# TREATMENT: the same `DEBUG = True` / `app.run(debug=True)` patterns appear
# inside a module docstring (documentation, never executed). CONTROL: a real
# DEBUG setting at the bottom. Context-window confidence (item ①) should
# down-rank the docstring occurrences while leaving the real setting untouched.
"""
Configuration example (documentation only — this block never runs):

    DEBUG = True
    app.run(debug=True)

Copy the snippet into settings.py and flip DEBUG off for production.
"""

import os

# CONTROL: a real, live setting. Must keep its default confidence.
DEBUG = True

ALLOWED_HOSTS = ["*"]
