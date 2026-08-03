"""Authorization decorators, in the shape of the Flask "View Decorators" pattern.

The `login_required` body is the documented one: it looks at `g.user` and sends
an anonymous caller to the login endpoint. `role_required` is the decorator
FACTORY form the same page shows for a parameterised check, and it is the only
place in this application where a role is compared against anything.

NEGATIVE FIXTURE for VG-SMELL-010's Python arm. Nothing here may be reported.
"""

from functools import wraps

from flask import abort, g, redirect, request, url_for


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login", next=request.url))
        return view(*args, **kwargs)

    return wrapped


def role_required(role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("auth.login", next=request.url))
            if g.user.role != role:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator
