"""
VibeGuard 検出テスト用の「わざと問題があるコード」サンプル。
本番では絶対に書いてはいけないアンチパターンを集めています。
各ブロックの先頭コメントが、想定される VibeGuard ルール ID の目安です。
"""

"""
Sample code designed to intentionally contain problems for VibeGuard detection testing.
This code contains anti-patterns that should absolutely never be written in a production environment.
The comments at the beginning of each block indicate the approximate expected VibeGuard rule ID.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)


# ---------------------------------------------------------------------------
# VG-SECRET-* : ハードコードされた秘密情報
# ---------------------------------------------------------------------------
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"
# NOTE: Stripe / Slack の見本は GitHub Push Protection を避けるため、
# 「2 つの文字列を + で連結」して書いています。VibeGuard の検出デモ用なので
# 実値を埋めず、この形のまま置いてください。
STRIPE_KEY = "sk_" + "live_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEX"
OPENAI_API_KEY = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
SLACK_WEBHOOK = "https://hooks.slack.com/" + "services/TEXAMPLE0/BEXAMPLE0/EXAMPLEEXAMPLEEXAMPLEEXA"

DB_PASSWORD = "P@ssw0rd123!"
JWT_SECRET = "supersecret"


# ---------------------------------------------------------------------------
# VG-FW-001 : Django/汎用 DEBUG フラグの本番有効化
# ---------------------------------------------------------------------------
DEBUG = True
ALLOWED_HOSTS = ["*"]


# ---------------------------------------------------------------------------
# VG-INJ-001 : SQL インジェクション（文字列連結 / f-string でのクエリ組み立て）
# ---------------------------------------------------------------------------
def get_user(conn: sqlite3.Connection, user_id: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    return cur.fetchone()


def search_user(conn: sqlite3.Connection, name: str):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name LIKE '%{name}%'")
    return cur.fetchall()


# ---------------------------------------------------------------------------
# VG-INJ-002 : コマンドインジェクション（shell=True / os.system にユーザー入力）
# ---------------------------------------------------------------------------
def ping_host(host: str):
    return os.system("ping -c 1 " + host)


def list_dir(path: str):
    return subprocess.check_output(f"ls -la {path}", shell=True)


# ---------------------------------------------------------------------------
# VG-INJ-003 : eval / exec によるコード実行
# ---------------------------------------------------------------------------
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))


@app.route("/run")
def run_code():
    code = request.args.get("code", "")
    exec(code)
    return "ok"


# ---------------------------------------------------------------------------
# VG-INJ-004 : 安全でないデシリアライズ（pickle / yaml.load）
# ---------------------------------------------------------------------------
@app.route("/load")
def load_state():
    blob = request.data
    return repr(pickle.loads(blob))


def parse_config(text: str):
    return yaml.load(text)  # yaml.safe_load を使うべき


# ---------------------------------------------------------------------------
# VG-CRYPTO-001 : 認証/署名向けの弱いハッシュ
# ---------------------------------------------------------------------------
def hash_password(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()


def fingerprint(token: str) -> str:
    return hashlib.sha1(token.encode()).hexdigest()


# ---------------------------------------------------------------------------
# VG-CRYPTO-002 : セキュリティ目的での弱い乱数
# ---------------------------------------------------------------------------
def new_session_id() -> str:
    return str(random.random())


def generate_reset_token() -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(16))


# ---------------------------------------------------------------------------
# VG-CRYPTO-003 : TLS 証明書検証の無効化
# ---------------------------------------------------------------------------
def fetch_internal(url: str):
    return requests.get(url, verify=False).text


# ---------------------------------------------------------------------------
# VG-AUTH-004 : 中身が常に True を返すバリデータ
# ---------------------------------------------------------------------------
def validate(token):
    return True


def is_authorized(user, action):
    return True


# ---------------------------------------------------------------------------
# VG-AUTH-005 : Django @csrf_exempt の無条件付与（Flask 風の例だが検出対象）
# ---------------------------------------------------------------------------
def csrf_exempt(view):
    return view


@csrf_exempt
@app.route("/delete_account", methods=["POST"])
def delete_account():
    user_id = request.form["user_id"]
    return f"deleted {user_id}"


# ---------------------------------------------------------------------------
# DVG-PY-001（構想・ソース層ルールでは未検出）: assert による認可チェック。
# python -O（optimize=1）では assert のコードが生成されず、認可ごと消える。
# ---------------------------------------------------------------------------
def delete_project(user, project_id, db):
    assert user.is_admin, "Admin only"
    db.delete_project(project_id)


# ---------------------------------------------------------------------------
# VG-FW-002 : Flask の debug=True 起動
# ---------------------------------------------------------------------------
def main():
    app.run(host="0.0.0.0", port=5000, debug=True)


# ---------------------------------------------------------------------------
# VG-QUAL-* : 本番経路に紛れ込んだモック/ダミーデータ
# ---------------------------------------------------------------------------
dummy_data = {"id": 1, "email": "test@example.com", "role": "admin"}
mock_user = {"name": "John Doe", "balance": 9999999}

TODO_REMOVE_ME = "fix before release"  # FIXME: ここをまだ直していない


# ---------------------------------------------------------------------------
# VG-QUAL-* : 例外の握りつぶし
# ---------------------------------------------------------------------------
def charge(card, amount):
    try:
        external_api_call(card, amount)
    except Exception:
        pass


def external_api_call(card, amount):
    raise NotImplementedError


if __name__ == "__main__":
    main()