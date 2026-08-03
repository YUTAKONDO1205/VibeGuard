"""Report endpoints. The third copy of the same policy, in a second file.

Two files is the MIN_FILES threshold and three sites is MIN_SITES, so this
fixture sits exactly on both — which is what makes it a useful control: a change
that loses one site turns the finding off and the test says so.
"""

from flask import Blueprint, jsonify, request

from .store import list_reports

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.route("/summary")
def report_summary():
    actor = request.environ["actor"]
    if actor.role != "admin":
        return jsonify(error="not permitted"), 403
    return jsonify(rows=[r.summary for r in list_reports()])
