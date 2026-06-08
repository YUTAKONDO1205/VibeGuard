from flask import Blueprint, jsonify

bp = Blueprint("billing", __name__)


@bp.route("/api/v1/refunds", methods=["POST"])
def issue_refund():
    raise NotImplementedError("refund flow")


@bp.route("/api/v1/refunds/<rid>", methods=["GET"])
def get_refund(rid):
    return jsonify(status="pending", id=rid)
