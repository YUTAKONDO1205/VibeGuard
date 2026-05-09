# VibeGuard sample: Flask app with debug server reachable.

from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

# VG-FW-003 — wildcard CORS at the resource level.
CORS(app, resources={r'/*': {'origins': '*'}})


@app.route('/hello')
def hello():
    return 'hi'


if __name__ == '__main__':
    # VG-FW-002 — Werkzeug debugger reachable on a public bind.
    app.run(host='0.0.0.0', debug=True)
