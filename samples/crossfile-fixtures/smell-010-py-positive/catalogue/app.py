"""Application factory. No `before_request` hook, no guard of any kind."""

from flask import Flask

from .orders import bp as orders_bp
from .reports import bp as reports_bp


def create_app():
    app = Flask(__name__)
    app.register_blueprint(orders_bp)
    app.register_blueprint(reports_bp)
    return app
