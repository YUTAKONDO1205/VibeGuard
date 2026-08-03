"""Application factory. Registers the two blueprints and nothing else."""

from flask import Flask

from .admin_area import bp as admin_bp
from .posts import bp as posts_bp


def create_app():
    app = Flask(__name__)
    app.register_blueprint(posts_bp)
    app.register_blueprint(admin_bp)
    return app
