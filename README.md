# Secure Student Portal — Complex Computing Activity

**Topic:** Secure Software Design & Development  
**Platform:** Flask (Python) Web Application  
**Author:** [Yasra Khan  / CR-22005]
            [Barira Tariq / CR-22017]
            [Aleeza Mehmood / CR-22024]
---

## 1. Project Overview

This project demonstrates **Secure Software Design principles** through a Flask-based Student Portal that supports:

- User Registration & Login
- Profile Viewing
- Student Search

The project is split into **two complete versions**:

| Version | Folder | Port | Description |
|---------|--------|------|-------------|
| Vulnerable | `vulnerable/` | 5000 | Contains 3 intentional security flaws |
| Secure | `secure/` | 5001 | All vulnerabilities eliminated |

---

## 2. How to Run

### Install dependencies

```bash
# Vulnerable version
cd vulnerable
pip install -r requirements.txt

# Secure version
cd secure
pip install -r requirements.txt
```

### Start the applications

```bash
# Terminal 1 — Vulnerable (port 5000)
cd vulnerable && python app.py

# Terminal 2 — Secure (port 5001)
cd secure && python app.py
```

### Run the automated proof-of-concept tests

```bash
pip install bcrypt bleach   # if not already installed
python proof_of_concept.py
```

Expected output: **6/6 tests PASS**

---

## 3. Security Vulnerabilities

---

### Vulnerability #1 — SQL Injection

**OWASP Category:** A03:2021 – Injection  
**Severity:** Critical

#### How it works (Vulnerable)

In `vulnerable/app.py`, the login route builds its query by string concatenation:

```python
query = (
    f"SELECT * FROM users WHERE username='{username}' "
    f"AND password='{password}'"
)
user = db.execute(query).fetchone()
```

**Exploit — Login Bypass:**

```
Username:  admin'--
Password:  anything
```

The executed query becomes:

```sql
SELECT * FROM users WHERE username='admin'--' AND password='anything'
```

The `--` starts a SQL comment, making the password check invisible. The attacker logs in as `admin` without knowing the real password.

**Exploit — UNION Data Dump (Search route):**

```
Search:  ' UNION SELECT id,username,password,email FROM users--
```

This returns all usernames and plaintext passwords from the database.

#### The Fix (Secure)

Use **parameterised queries** with `?` placeholders. The DB driver sends value and SQL separately — the value is always treated as data, never as executable SQL:

```python
# SECURE — parameterised login
user = db.execute(
    "SELECT * FROM users WHERE username = ?", (username,)
).fetchone()

# SECURE — parameterised search
results = db.execute(
    "SELECT id, username, fullname, email FROM users WHERE fullname LIKE ?",
    (f"%{query_str}%",)
).fetchall()
```

**Proof from automated test:**

```
✓ PASS  VULNERABLE: SQL injection 'admin'-- logs in without the real password
         Injected query returned row: {'id': 1, 'username': 'admin', ...}

✓ PASS  SECURE:     SQL injection payload finds no user (parameterised query)
         Parameterised ? treats the entire string as data — no user returned
```

---

### Vulnerability #2 — Stored Cross-Site Scripting (XSS)

**OWASP Category:** A03:2021 – Injection  
**Severity:** High

#### How it works (Vulnerable)

In `vulnerable/app.py`, the bio field is stored with **no sanitisation**:

```python
bio = request.form.get("bio", "")
db.execute("INSERT INTO users ... VALUES (?,?,?,?,?)",
           (username, password, fullname, email, bio))
```

In `vulnerable/templates/profile.html`, it is rendered with Jinja2's `| safe` filter, which **disables escaping**:

```html
<div class="bio-box">{{ user.bio | safe }}</div>
```

**Exploit — Stored XSS Payload (enter in Bio field at registration):**

```html
<script>alert('XSS: ' + document.cookie)</script>
```

Every time any user visits the profile page, this script executes in their browser — stealing cookies, redirecting them, or performing actions on their behalf.

#### The Fix (Secure)

**Two-layer defence:**

1. **Input sanitisation** with `bleach.clean()` before storage:

```python
import bleach

ALLOWED_TAGS  = ["b", "i", "em", "strong", "p", "br"]
ALLOWED_ATTRS = {}

safe_bio = bleach.clean(
    raw_bio, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True
)
# <script>alert(...)</script> becomes: alert(...)  — inert plain text
```

2. **Output encoding** via Jinja2 auto-escaping (remove `| safe`):

```html
<!-- SECURE — auto-escaping ON, no | safe filter -->
<div class="bio-box">{{ user.bio }}</div>
```

Any residual `<`, `>` characters are entity-encoded as `&lt;` and `&gt;`.

**Proof from automated test:**

```
✓ PASS  VULNERABLE: XSS payload stored verbatim, rendered with | safe
         Stored bio: <script>alert('XSS: '+document.cookie)</script>Hello

✓ PASS  SECURE:     bleach.clean() strips <script> tags — no executable script element
         Sanitised bio: 'alert('XSS: '+document.cookie)Hello' ← plain text only
```

---

### Vulnerability #3 — Broken Authentication

**OWASP Category:** A07:2021 – Identification and Authentication Failures  
**Severity:** Critical  
**Sub-issues:** plaintext passwords · weak session secret · no CSRF protection · debug mode

#### How it works (Vulnerable)

```python
# 3a — hard-coded, trivially guessable secret key
app.secret_key = "secret"

# 3b — password stored as plaintext
db.execute(
    "INSERT INTO users (username,password,...) VALUES (?,?,?,?,?)",
    (username, password, ...)   # password = "mypassword" literally
)

# 3c — no CSRF protection; no login_required decorator robustness
# 3d — debug=True leaks stack traces in production
app.run(debug=True)
```

**Impact:**
- Any DB read (via SQL injection or direct file access) exposes every password immediately.
- A trivial secret key allows session cookie forgery — an attacker crafts a session as any user ID.
- No CSRF protection: a malicious page can trick a logged-in user into submitting forms.

#### The Fix (Secure)

```python
# 3a — cryptographically random 256-bit secret
app.secret_key = secrets.token_hex(32)

# 3b — bcrypt with 12 rounds (slow, salted, one-way)
pw_hash = bcrypt.hashpw(
    password.encode(), bcrypt.gensalt(rounds=12)
).decode()
db.execute("INSERT INTO users (username,password_hash,...) VALUES (?,?,?,?,?)",
           (username, pw_hash, ...))

# Verification (timing-safe)
if bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
    ...

# 3c — CSRF protection via Flask-WTF
csrf = CSRFProtect(app)  # all POST forms require hidden token

# Secure session cookie settings
app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = "Lax",
    PERMANENT_SESSION_LIFETIME = 1800,
)

# 3d — debug off
app.run(debug=False)
```

**Proof from automated test:**

```
✓ PASS  VULNERABLE: password 'secret123' stored as plaintext in DB
         DB value: 'secret123' — any DB read leaks all passwords instantly

✓ PASS  SECURE:     bcrypt hash stored — correct pw accepted, wrong pw rejected, hash ≠ plaintext
         Hash (first 29 chars): $2b$12$N987dSVkuJVwt2zBTNJ04e… | correct→True wrong→False
```

---

## 4. Vulnerability vs Fix Comparison Table

| # | Vulnerability | OWASP | Vulnerable Code | Fix Applied |
|---|--------------|-------|-----------------|-------------|
| 1 | SQL Injection | A03 | String concatenation in `f"...'{username}'..."` | Parameterised `?` placeholders |
| 2 | Stored XSS | A03 | `{{ user.bio \| safe }}` + no sanitisation | `bleach.clean()` + Jinja2 auto-escape |
| 3 | Broken Auth | A07 | Plaintext passwords, `secret_key = "secret"` | bcrypt hashing, `secrets.token_hex(32)`, CSRF, HttpOnly cookies |

---

## 5. Security Principles Demonstrated

| Principle | Applied In |
|-----------|-----------|
| **Defence in Depth** | XSS: bleach on input AND auto-escape on output |
| **Least Privilege** | Search query selects only needed columns, never `password_hash` |
| **Parameterisation** | All SQL uses `?` placeholders |
| **Secure Defaults** | `debug=False`, `HttpOnly`, `SameSite=Lax` |
| **Input Validation** | WTForms validators on all fields (length, email format, required) |
| **Slow Hashing** | bcrypt with 12 rounds makes brute-force impractical |
| **Session Hardening** | Random secret, 30-min timeout, session fixation prevention |

---

## 6. Proof of Concept Test Results

Run `python proof_of_concept.py` from the project root:

```
════════════════════════════════════════════════════════════
  VULNERABILITY #1 — SQL Injection (login bypass)
════════════════════════════════════════════════════════════
  ✓ PASS  VULNERABLE: SQL injection 'admin'-- logs in without the real password
  ✓ PASS  SECURE:     SQL injection payload finds no user (parameterised query)

════════════════════════════════════════════════════════════
  VULNERABILITY #2 — Stored XSS (bio field)
════════════════════════════════════════════════════════════
  ✓ PASS  VULNERABLE: XSS payload stored verbatim, rendered with | safe
  ✓ PASS  SECURE:     bleach.clean() strips <script> tags — no executable script

════════════════════════════════════════════════════════════
  VULNERABILITY #3 — Broken Authentication (plaintext passwords)
════════════════════════════════════════════════════════════
  ✓ PASS  VULNERABLE: password stored as plaintext in DB
  ✓ PASS  SECURE:     bcrypt hash — correct pw accepted, wrong pw rejected

════════════════════════════════════════════════════════════
  SUMMARY
════════════════════════════════════════════════════════════
  Tests run : 6
  Passed    : 6

  All 6 tests passed — vulnerabilities proven and fixes verified.
```

---

## 7. Project File Structure

```
student_portal/
├── proof_of_concept.py       ← automated tests (run first)
├── README.md                 ← this file
│
├── vulnerable/               ← VULNERABLE version (port 5000)
│   ├── app.py
│   ├── requirements.txt
│   └── templates/
│       ├── login.html
│       ├── register.html
│       ├── profile.html
│       └── search.html
│
└── secure/                   ← SECURE version (port 5001)
    ├── app.py
    ├── requirements.txt
    └── templates/
        ├── login.html
        ├── register.html
        ├── profile.html
        └── search.html
```

---

## 8. References

- OWASP Top 10 (2021): https://owasp.org/Top10/
- OWASP SQL Injection Prevention Cheat Sheet
- OWASP XSS Prevention Cheat Sheet
- NIST SP 800-63B — Digital Identity Guidelines (password storage)
- Flask Security Documentation
- bcrypt: https://pypi.org/project/bcrypt/
- bleach: https://pypi.org/project/bleach/
