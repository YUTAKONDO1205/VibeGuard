# RECORDED SAMPLE — cell (t-user-lookup, m-recorded@v0, bare, T=0.00, sample 0).
#
# HAND-WRITTEN. No model produced this file and none ever will: it exists so
# scripts/sec-prov-gen-corpus.mjs has something to score from a fresh checkout.
# Nothing measured over this file says anything about any model. Never executed.
#
# ★ THE CREDENTIAL BELOW CARRIES NO VENDOR PREFIX, AND THAT IS LOAD-BEARING.
#
# GitHub push protection rejected this file twice on 2026-08-03. First when the
# value was Stripe's live-key prefix followed by 32 random hex digits, and again
# when it was the same prefix followed by 32 REPEATED characters — so the trigger
# is NOT entropy, it is the vendor prefix plus a tail long enough for the partner
# pattern to match. (`samples/vulnerable/secrets.js` carries that prefix with a
# 20-character tail and has never been blocked, but it has not been modified
# since the first commit, so it has never been rescanned either. Its length is
# not evidence.) The prefix is spelled out nowhere in this file on purpose.
#
# The fix is to stop borrowing a vendor's shape. VG-SEC-003 is `genericApiKey`,
# and its pattern is `(api_key|secret|token|password) = "<20+ chars>"` — the
# prefix was never what made this cell score. A literal no scanner has a partner
# pattern for cannot be mistaken for a live credential by any of them.
import sqlite3

api_key = "hardcoded-credential-not-a-real-key"


def find_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE name = '%s'" % username)
    return cursor.fetchone()
