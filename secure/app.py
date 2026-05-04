"""
=============================================================
  SECURE VERSION — Student Portal
  Fixes applied:
    Fix #1: Parameterised queries  → SQL Injection eliminated
    Fix #2: Auto-escaping + bleach → Stored XSS eliminated
    Fix #3: bcrypt hashing + strong session config
            → Broken Authentication eliminated
=============================================================
"""

import os
import secrets
import sqlite3

import bleach
import bcrypt
from flask import (Flask, request, render_template, redirect,
                   url_for, session, flash)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Email, Length

# ── app setup ─────────────────────────────────────────────────────────────────

app = Flask(__name__)

# FIX #3a – strong random secret key (32 bytes = 256-bit entropy)
app.secret_key = secrets.token_hex(32)

# FIX #3b – secure session cookie settings
app.config.update(
    SESSION_COOKIE_HTTPONLY = True,   # JS cannot access cookie
    SESSION_COOKIE_SAMESITE = "Lax",  # CSRF mitigation
    SESSION_COOKIE_SECURE   = False,  # set True in production (HTTPS)
    PERMANENT_SESSION_LIFETIME = 1800,  # 30-minute session timeout
    WTF_CSRF_ENABLED = True,
)

# FIX #3c – CSRF protection on all POST forms
csrf = CSRFProtect(app)

DB_PATH = "students_secure.db"

# ── allowed HTML tags for bio (bleach whitelist) ──────────────────────────────
ALLOWED_TAGS   = ["b", "i", "em", "strong", "p", "br"]
ALLOWED_ATTRS  = {}   # no attributes allowed


# ── WTForms ───────────────────────────────────────────────────────────────────

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=64)])
    password = PasswordField("Password", validators=[DataRequired()])


class RegisterForm(FlaskForm):
    fullname = StringField("Full Name", validators=[DataRequired(), Length(max=128)])
    username = StringField("Username",  validators=[DataRequired(), Length(min=3, max=64)])
    email    = StringField("Email",     validators=[DataRequired(), Email(), Length(max=128)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    bio      = TextAreaField("Bio",     validators=[Length(max=1000)])


class SearchForm(FlaskForm):
    q = StringField("Search", validators=[Length(max=128)])


# ── helpers ───────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT    UNIQUE NOT NULL,
                password_hash TEXT   NOT NULL,   -- FIX #3: bcrypt hash only
                fullname     TEXT,
                email        TEXT,
                bio          TEXT
            )
        """)
        existing = db.execute(
            "SELECT id FROM users WHERE username='admin'"
        ).fetchone()
        if not existing:
            # FIX #3: hash the seed password
            pw_hash = bcrypt.hashpw(b"Admin@secure1", bcrypt.gensalt(rounds=12))
            db.execute(
                "INSERT INTO users (username,password_hash,fullname,email,bio) "
                "VALUES (?,?,?,?,?)",
                ("admin", pw_hash.decode(), "Admin User",
                 "admin@uni.edu", "System administrator")
            )
        db.commit()


def login_required(f):
    """Decorator – redirects to login if session is missing."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.encode()

        # ════════════════════════════════════════════════════════════
        # FIX #1 — PARAMETERISED QUERY prevents SQL Injection.
        # The ? placeholder causes the DB driver to treat the value
        # as data, never as executable SQL. Injection impossible.
        # ════════════════════════════════════════════════════════════
        db   = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # FIX #3 – timing-safe bcrypt comparison
        if user and bcrypt.checkpw(password, user["password_hash"].encode()):
            session.clear()                     # prevent session fixation
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session.permanent   = True
            return redirect(url_for("profile"))
        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email    = form.email.data.strip()
        fullname = form.fullname.data.strip()
        raw_bio  = form.bio.data or ""

        # ════════════════════════════════════════════════════════════
        # FIX #2 — STORED XSS prevention via bleach sanitisation.
        # bleach.clean() strips all tags not on the whitelist and
        # escapes any remaining special characters, so a <script>
        # payload is rendered as inert text, never executed.
        # ════════════════════════════════════════════════════════════
        safe_bio = bleach.clean(
            raw_bio,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRS,
            strip=True
        )

        # FIX #3 – bcrypt hash; plaintext password never stored
        pw_hash = bcrypt.hashpw(
            form.password.data.encode(), bcrypt.gensalt(rounds=12)
        ).decode()

        try:
            with get_db() as db:
                # FIX #1 – parameterised INSERT
                db.execute(
                    "INSERT INTO users "
                    "(username, password_hash, fullname, email, bio) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (username, pw_hash, fullname, email, safe_bio)
                )
                db.commit()
            flash("Account created — please sign in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken.", "error")

    return render_template("register.html", form=form)


@app.route("/profile")
@login_required
def profile():
    db   = get_db()
    user = db.execute(
        # FIX #1 – parameterised SELECT
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    return render_template("profile.html", user=user)


@app.route("/search")
@login_required
def search():
    form      = SearchForm(request.args, meta={"csrf": False})
    results   = []
    query_str = ""

    if form.validate() and form.q.data:
        query_str = form.q.data.strip()
        db        = get_db()
        # ════════════════════════════════════════════════════════════
        # FIX #1 – parameterised LIKE query.
        # The wildcard characters are added by Python, not the user.
        # A UNION injection attempt is treated as a literal string.
        # ════════════════════════════════════════════════════════════
        results = db.execute(
            "SELECT id, username, fullname, email "
            "FROM users WHERE fullname LIKE ?",
            (f"%{query_str}%",)
        ).fetchall()

    return render_template("search.html", form=form,
                           results=results, query=query_str)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    # FIX #3d – debug=False in all deployments
    app.run(debug=False, port=5001)
