"""The moderator area.

The third route-level authorization decision, delegated to the parameterised
decorator from `security.py`. The tenant narrowing in the body is again an
object-level concern.
"""

from flask import Blueprint, g, jsonify

from .security import role_required
from .store import list_audit_entries

bp = Blueprint("admin_area", __name__, url_prefix="/admin")


@bp.route("/audit")
@role_required("admin")
def audit_log():
    entries = list_audit_entries()
    if g.user.role != "owner":
        entries = [e for e in entries if e.tenant_id == g.user.tenant_id]
    return jsonify(entries=[e.summary for e in entries])
