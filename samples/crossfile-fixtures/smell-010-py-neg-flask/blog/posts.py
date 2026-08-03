"""Post endpoints.

Two route-level authorization decisions, both delegated to `@login_required`.
The role comparisons in the bodies are OBJECT-level: they narrow what an
already-admitted caller may see or delete, which is the layered design a route
guard cannot express because the resource is not known until the handler runs.
"""

from flask import Blueprint, abort, g, jsonify

from .security import login_required
from .store import find_post, list_posts

bp = Blueprint("posts", __name__, url_prefix="/posts")


@bp.route("/")
@login_required
def list_visible_posts():
    posts = list_posts()
    if g.user.role != "editor":
        posts = [p for p in posts if p.author_id == g.user.id]
    return jsonify(posts=[p.title for p in posts])


@bp.route("/<int:post_id>", methods=["DELETE"])
@login_required
def delete_post(post_id):
    post = find_post(post_id)
    if post is None:
        abort(404)
    if post.author_id != g.user.id and g.user.role != "editor":
        abort(403)
    post.retire()
    return "", 204
