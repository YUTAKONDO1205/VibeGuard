import os
import secrets
import subprocess

import requests
import yaml


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def show_log(commit_id):
    subprocess.run(["git", "log", commit_id], check=True)


def fetch():
    # Reads from environment, not embedded secret
    api_key = os.environ["STRIPE_API_KEY"]
    return requests.get("https://api.example.com/x", headers={"Authorization": api_key})


def load_config(blob):
    return yaml.safe_load(blob)


def make_token():
    return secrets.token_urlsafe(32)
