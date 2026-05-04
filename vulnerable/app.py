"""
=============================================================
  VULNERABLE VERSION — Student Portal
  WARNING: This file contains INTENTIONAL security flaws
  for educational / academic demonstration purposes only.
=============================================================

Vulnerability #1: SQL Injection  (login & search routes)
Vulnerability #2: Stored XSS     (registration & profile)
Vulnerability #3: Broken Authentication – plaintext passwords
                  + no session protection
=============================================================
"""

from flask import Flask, request, render_template, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
# VULN #3b – weak, hard-coded secret key (session tampering trivial)
app.secret_key = "secret"

DB_PATH = "students.db"


# ── helpers ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    UNIQUE NOT NULL,
                password TEXT    NOT NULL,          -- VULN #3: plaintext
                fullname TEXT,
                email    TEXT,
                bio      TEXT
            )
        """)
        # seed demo account
        existing = db.execute(
            "SELECT id FROM users WHERE username='admin'"
        ).fetchone()
        if not existing:
            db.execute(
                "INSERT INTO users (username,password,fullname,email,bio) "
                "VALUES ('admin','admin123','Admin User','admin@uni.edu','System administrator')"
            )
        db.commit()


# ── routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # ════════════════════════════════════════════════════════════
        # VULNERABILITY #1 — SQL INJECTION
        # User input is concatenated directly into the SQL query.
        # Payload example:
        #   username: admin'--
        #   password: anything
        # This comments out the password check, granting access without
        # knowing the real password.
        # ════════════════════════════════════════════════════════════
        query = (
            f"SELECT * FROM users WHERE username='{username}' "
            f"AND password='{password}'"
        )
        db   = get_db()
        user = db.execute(query).fetchone()

        if user:
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("profile"))
        else:
            error = "Invalid credentials."

    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        fullname = request.form["fullname"]
        email    = request.form["email"]
        bio      = request.form.get("bio", "")

        # ════════════════════════════════════════════════════════════
        # VULNERABILITY #2 — STORED XSS
        # Bio (and fullname / email) are stored and later rendered
        # without sanitisation via {{ user.bio | safe }}.
        # Payload example (in Bio field):
        #   <script>alert('XSS – cookies: ' + document.cookie)</script>
        # Every visitor who views the profile executes the script.
        # ════════════════════════════════════════════════════════════
        try:
            with get_db() as db:
                # VULN #3: password stored as plaintext
                db.execute(
                    "INSERT INTO users (username,password,fullname,email,bio) "
                    "VALUES (?,?,?,?,?)",
                    (username, password, fullname, email, bio)
                )
                db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            error = "Username already taken."

    return render_template("register.html", error=error)


@app.route("/profile")
def profile():
    # VULN #3c – no proper auth check; only a truthy session value needed
    if "user_id" not in session:
        return redirect(url_for("login"))

    db   = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id=?", (session["user_id"],)
    ).fetchone()
    return render_template("profile.html", user=user)


@app.route("/search")
def search():
    if "user_id" not in session:
        return redirect(url_for("login"))

    query_str = request.args.get("q", "")
    results   = []

    if query_str:
        # ════════════════════════════════════════════════════════════
        # VULNERABILITY #1 (cont.) — SQL INJECTION in search
        # Payload example:
        #   q: ' UNION SELECT id,username,password,email,bio,fullname FROM users--
        # Dumps all usernames and PLAINTEXT passwords.
        # ════════════════════════════════════════════════════════════
        raw_sql = (
            f"SELECT id, username, fullname, email "
            f"FROM users WHERE fullname LIKE '%{query_str}%'"
        )
        db      = get_db()
        results = db.execute(raw_sql).fetchall()

    return render_template("search.html", results=results, query=query_str)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    # VULN #3d – debug=True in production leaks stack traces
    app.run(debug=True, port=5000)
