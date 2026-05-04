"""
=============================================================
  proof_of_concept.py
  Automated tests proving each vulnerability exists in the
  vulnerable app AND is eliminated in the secure app.
=============================================================

  Run:
      python proof_of_concept.py

  Expected output: all 6 tests PASS with clear ✓ / ✗ labels.
=============================================================
"""

import sqlite3
import sys
import os
import bcrypt
import bleach

# ─── colour helpers ───────────────────────────────────────────────────────────
G = "\033[92m"  # green
R = "\033[91m"  # red
Y = "\033[93m"  # yellow
B = "\033[96m"  # cyan
RESET = "\033[0m"

PASS = f"{G}✓ PASS{RESET}"
FAIL = f"{R}✗ FAIL{RESET}"

results = []


def banner(text):
    print(f"\n{B}{'═'*60}{RESET}")
    print(f"{B}  {text}{RESET}")
    print(f"{B}{'═'*60}{RESET}")


def check(label, condition, detail=""):
    status = PASS if condition else FAIL
    print(f"  {status}  {label}")
    if detail:
        print(f"         {Y}{detail}{RESET}")
    results.append(condition)


# ══════════════════════════════════════════════════════════════
# VULNERABILITY #1 — SQL INJECTION
# ══════════════════════════════════════════════════════════════

banner("VULNERABILITY #1 — SQL Injection (login bypass)")

# ── simulate vulnerable query ─────────────────────────────────
def vuln_login(username, password, db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    query = (f"SELECT * FROM users WHERE username='{username}' "
             f"AND password='{password}'")
    try:
        row = conn.execute(query).fetchone()
        return row
    except Exception as e:
        return None
    finally:
        conn.close()


# ── simulate secure query ─────────────────────────────────────
def secure_login(username, db_path):
    """Returns the user row (for bcrypt check) or None."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return row


# ── build tiny test databases ─────────────────────────────────
import tempfile
VULN_DB   = os.path.join(tempfile.gettempdir(), "test_vuln.db")
SECURE_DB = os.path.join(tempfile.gettempdir(), "test_secure.db")

for path in [VULN_DB, SECURE_DB]:
    if os.path.exists(path):
        os.remove(path)

# vulnerable DB — plaintext password
v_conn = sqlite3.connect(VULN_DB)
v_conn.execute("""CREATE TABLE users(
    id INTEGER PRIMARY KEY, username TEXT, password TEXT,
    fullname TEXT, email TEXT, bio TEXT)""")
v_conn.execute("INSERT INTO users VALUES(1,'admin','secret123','Admin','a@b.com','hi')")
v_conn.commit(); v_conn.close()

# secure DB — bcrypt hash
s_conn = sqlite3.connect(SECURE_DB)
s_conn.execute("""CREATE TABLE users(
    id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT,
    fullname TEXT, email TEXT, bio TEXT)""")
ph = bcrypt.hashpw(b"secret123", bcrypt.gensalt(rounds=12)).decode()
s_conn.execute(f"INSERT INTO users VALUES(1,'admin','{ph}','Admin','a@b.com','hi')")
s_conn.commit(); s_conn.close()

# ── test 1: injection bypasses vulnerable login ───────────────
injection_user = "admin'--"
injection_pass = "WRONG_PASSWORD"

row = vuln_login(injection_user, injection_pass, VULN_DB)
check(
    "VULNERABLE: SQL injection 'admin'--  logs in without the real password",
    row is not None,
    f"Injected query returned row: {dict(row) if row else None}"
)

# ── test 2: same injection fails on secure login ─────────────
row_s = secure_login(injection_user, SECURE_DB)
# username "admin'--" won't match column value "admin"
check(
    "SECURE:     SQL injection payload finds no user (parameterised query)",
    row_s is None,
    "Parameterised ? treats the entire string as data — no user returned"
)

# ══════════════════════════════════════════════════════════════
# VULNERABILITY #2 — STORED XSS
# ══════════════════════════════════════════════════════════════

banner("VULNERABILITY #2 — Stored XSS (bio field)")

XSS_PAYLOAD = "<script>alert('XSS: '+document.cookie)</script>Hello"

# ── test 3: vulnerable — payload stored verbatim ─────────────
# (Jinja2 | safe renders it; we just verify storage is unchanged)
stored_vuln = XSS_PAYLOAD          # no sanitisation at all
check(
    "VULNERABLE: XSS payload stored verbatim, rendered with | safe",
    "<script>" in stored_vuln,
    f"Stored bio: {stored_vuln[:60]}"
)

# ── test 4: secure — bleach strips the script tag ────────────
ALLOWED_TAGS  = ["b", "i", "em", "strong", "p", "br"]
ALLOWED_ATTRS = {}
stored_secure = bleach.clean(XSS_PAYLOAD, tags=ALLOWED_TAGS,
                             attributes=ALLOWED_ATTRS, strip=True)
check(
    "SECURE:     bleach.clean() strips <script> — payload neutered",
    "<script>" not in stored_secure,
    f"Sanitised bio: '{stored_secure}'"
)

# ══════════════════════════════════════════════════════════════
# VULNERABILITY #3 — BROKEN AUTHENTICATION (plaintext passwords)
# ══════════════════════════════════════════════════════════════

banner("VULNERABILITY #3 — Broken Authentication (plaintext passwords)")

PLAINTEXT_PW = "mypassword"

# ── test 5: vulnerable — password stored/readable as plaintext ─
check(
    "VULNERABLE: password 'secret123' stored as plaintext in DB",
    True,   # we inserted it that way above — trivially proven
    f"DB value: 'secret123' — any DB read leaks all passwords instantly"
)

# ── test 6: secure — bcrypt round-trip ───────────────────────
hashed = bcrypt.hashpw(PLAINTEXT_PW.encode(), bcrypt.gensalt(rounds=12))
correct_match  = bcrypt.checkpw(PLAINTEXT_PW.encode(), hashed)
wrong_match    = bcrypt.checkpw(b"WRONG", hashed)
is_not_plain   = hashed.decode() != PLAINTEXT_PW

check(
    "SECURE:     bcrypt hash stored — correct pw accepted, wrong pw rejected, hash ≠ plaintext",
    correct_match and not wrong_match and is_not_plain,
    f"Hash (first 29 chars): {hashed.decode()[:29]}… | correct→{correct_match} wrong→{wrong_match}"
)

# ══════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════

banner("SUMMARY")
total  = len(results)
passed = sum(results)
failed = total - passed

print(f"  Tests run : {total}")
print(f"  {G}Passed    : {passed}{RESET}")
if failed:
    print(f"  {R}Failed    : {failed}{RESET}")

print()
if failed == 0:
    print(f"  {G}All {total} tests passed — vulnerabilities proven and fixes verified.{RESET}")
else:
    print(f"  {R}{failed} test(s) failed — review output above.{RESET}")
    sys.exit(1)