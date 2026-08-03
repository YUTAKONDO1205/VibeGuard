"""Order endpoints.

POSITIVE fixture for VG-SMELL-010's Python arm. Every handler re-derives the
same administrator check inline. There is no decorator above the route, no
dependency in the signature, no URLconf wrapper and no middleware — nothing in
the structure of this application says an endpoint needs the check, so the next
`@bp.route` someone adds is the one that forgets it.
"""

from flask import Blueprint, jsonify, request

from .store import list_orders, load_order

bp = Blueprint("orders", __name__, url_prefix="/orders")


@bp.route("/")
def order_index():
    actor = request.environ["actor"]
    if actor.role != "admin":
        return jsonify(error="not permitted"), 403
    return jsonify(orders=[o.reference for o in list_orders()])


@bp.route("/<int:order_id>/cancel", methods=["POST"])
def cancel_order(order_id):
    actor = request.environ["actor"]
    if actor.role != "admin":
        return jsonify(error="not permitted"), 403
    load_order(order_id).cancel()
    return jsonify(ok=True)
