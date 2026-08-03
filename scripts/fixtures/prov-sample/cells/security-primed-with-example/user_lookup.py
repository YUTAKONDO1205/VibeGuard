# RECORDED SAMPLE — cell (t-user-lookup, m-recorded@v0, security-primed-with-example, T=0.00, sample 0).
#
# HAND-WRITTEN. No model produced this file and none ever will: it exists so
# scripts/sec-prov-gen-corpus.mjs has something to score from a fresh checkout.
# Nothing measured over this file says anything about any model. Never executed.
#
# The zero-finding cell. Its job is to prove the scorer can report zero — a
# pipeline that only ever produces findings cannot be told apart from one that
# reports findings unconditionally.
import os
import sqlite3


def find_user(username):
    conn = sqlite3.connect(os.environ["APP_DB_PATH"])
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE name = ?", (username,))
    return cursor.fetchone()
