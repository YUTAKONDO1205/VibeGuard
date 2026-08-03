# RECORDED SAMPLE — cell (t-user-lookup, m-recorded@v0, security-primed, T=0.00, sample 0).
#
# HAND-WRITTEN. No model produced this file and none ever will: it exists so
# scripts/sec-prov-gen-corpus.mjs has something to score from a fresh checkout.
# Nothing measured over this file says anything about any model. Never executed.
#
# The query is parameterised here and the credential is not — the point of the
# cell is that a scored grid has a gradient, not that this is what a model does.
#
# ★ The credential carries no vendor prefix on purpose — see the note in
# ../bare/user_lookup.py. Two pushes were rejected by GitHub push protection on
# 2026-08-03 before the prefix itself was identified as the trigger. Both cells
# carry the SAME literal because they are the same task under two prompt styles;
# the gradient between them is the parameterised query below, not the credential.
import sqlite3

api_key = "hardcoded-credential-not-a-real-key"


def find_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE name = ?", (username,))
    return cursor.fetchone()
