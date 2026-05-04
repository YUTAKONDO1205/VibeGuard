import sqlite3


def get_user(conn, user_id):
    # AI-prone: building SQL with string concatenation
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchone()


def delete_session(conn, sid):
    cur = conn.cursor()
    cur.execute("DELETE FROM sessions WHERE id = " + sid)
