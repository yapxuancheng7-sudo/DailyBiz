import os
import sys
import re
import hmac
import time
import uuid
import getpass
import sqlite3
import secrets
import imagehash
from PIL import Image
from decimal import Decimal, InvalidOperation
from pathlib import Path
from datetime import date, datetime, timedelta
from functools import wraps
from flask import (
    Flask, request, redirect, url_for, session,
    flash, render_template_string, send_from_directory,
    abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# ==========================================
# 1. APP CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = INSTANCE_DIR / "uploads"

INSTANCE_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

DATABASE = INSTANCE_DIR / "dailybiz.db"

# Keep the secret key between restarts.
SECRET_FILE = INSTANCE_DIR / "secret_key"

if SECRET_FILE.exists():
    SECRET_KEY = SECRET_FILE.read_text().strip()
else:
    SECRET_KEY = secrets.token_hex(32)
    SECRET_FILE.write_text(SECRET_KEY)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set COOKIE_SECURE=1 when the site runs on HTTPS.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE") == "1"

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}

USERNAME_RE = re.compile(r"[a-zA-Z0-9_.-]{3,40}")
ADMIN_BUSINESS_NAME = "DailyBiz Administration"


# ==========================================
# 2. DATABASE
# ==========================================

def connect_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    db = connect_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            business_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'owner',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            category TEXT NOT NULL,
            amount_cents INTEGER NOT NULL,
            description TEXT DEFAULT '',
            txn_date TEXT NOT NULL,
            receipt TEXT DEFAULT '',
            receipt_hash TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    columns = db.execute("PRAGMA table_info(transactions)").fetchall()
    column_names = [column[1] for column in columns]

    if "receipt_hash" not in column_names:
        db.execute("""
            ALTER TABLE transactions
            ADD COLUMN receipt_hash TEXT DEFAULT ''
        """)

    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_transactions_user_date
        ON transactions(user_id, txn_date)
    """)

    db.commit()
    db.close()


init_db()


# ==========================================
# 2B. ADMIN ACCOUNT (single place for all admin creation)
# ==========================================
# Used by:
#   1. ensure_admin()      -> environment variables at startup
#   2. /admin-recovery     -> web page protected by ADMIN_RECOVERY_KEY
#   3. create_admin()      -> command line: python app.py create-admin

def validate_admin_credentials(username, password):
    """Return an error message, or None if everything is valid."""
    if not USERNAME_RE.fullmatch(username):
        return ("Invalid username. Use 3-40 letters, numbers, "
                "dots, underscores or hyphens.")

    if len(password) < 12 or len(password) > 128:
        return "Password must be between 12 and 128 characters."

    return None


def upsert_admin(username, password, reset_existing=True):
    """
    Create an admin, or reset the password of an existing admin.
    Returns (ok, message).
    Never touches a customer (owner) account with the same username.
    """
    username = username.strip()

    error = validate_admin_credentials(username, password)
    if error:
        return False, error

    db = connect_db()

    try:
        existing = db.execute(
            "SELECT id, role FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing:
            if existing["role"] != "admin":
                return False, "This username belongs to a customer account."

            if not reset_existing:
                return True, "Admin account already exists."

            db.execute("""
                UPDATE users
                SET password_hash = ?, active = 1
                WHERE id = ?
            """, (generate_password_hash(password), existing["id"]))

            db.commit()
            return True, "Admin account recovered successfully!"

        db.execute("""
            INSERT INTO users
            (username, password_hash, business_name,
             role, active, created_at)
            VALUES (?, ?, ?, 'admin', 1, ?)
        """, (
            username,
            generate_password_hash(password),
            ADMIN_BUSINESS_NAME,
            datetime.now().strftime("%Y-%m-%d %H:%M")
        ))

        db.commit()
        return True, "Admin account created successfully!"

    except sqlite3.IntegrityError:
        db.rollback()
        return False, "Could not create admin account."

    finally:
        db.close()


def ensure_admin():
    """
    Startup: create the admin from ADMIN_USERNAME / ADMIN_PASSWORD.
    If the admin already exists its password is NOT changed, unless
    ADMIN_FORCE_RESET=1 is set.
    """
    username = os.environ.get("ADMIN_USERNAME")
    password = os.environ.get("ADMIN_PASSWORD")

    if not username or not password:
        print("[admin] ADMIN_USERNAME / ADMIN_PASSWORD not set, skipping.")
        return

    force = os.environ.get("ADMIN_FORCE_RESET") == "1"
    ok, message = upsert_admin(username, password, reset_existing=force)

    print(("[admin] " if ok else "[admin ERROR] ") + message)


ensure_admin()


# ==========================================
# 3. SECURITY AND HELPERS
# ==========================================

@app.before_request
def prepare_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")

        if not expected or not hmac.compare_digest(submitted, expected):
            abort(400, description="Invalid security token. Refresh and try again.")


def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    db = connect_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ? AND active = 1",
        (user_id,)
    ).fetchone()
    db.close()

    if not user:
        session.clear()

    return user


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def owner_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = current_user()

        if not user:
            return redirect(url_for("login"))

        if user["role"] != "owner":
            abort(403)

        return func(*args, **kwargs)
    return wrapper


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = current_user()

        if not user:
            return redirect(url_for("login"))

        if user["role"] != "admin":
            abort(403)

        return func(*args, **kwargs)
    return wrapper


@app.route("/admin-recovery", methods=["GET", "POST"])
def admin_recovery():

    recovery_key = os.environ.get("ADMIN_RECOVERY_KEY")

    if not recovery_key:
        return "Admin recovery is not configured.", 503

    message = ""

    if request.method == "POST":

        submitted_key = request.form.get("recovery_key", "")

        if not hmac.compare_digest(submitted_key, recovery_key):
            time.sleep(1)  # slow down guessing
            message = "Invalid recovery key."

        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            ok, message = upsert_admin(username, password)

    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>DailyBiz Admin Recovery</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: #f4f6f9;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    margin: 0;
                }
                .box {
                    background: white;
                    padding: 30px;
                    border-radius: 12px;
                    width: 90%;
                    max-width: 380px;
                    box-shadow: 0 4px 20px #0001;
                }
                input, button {
                    box-sizing: border-box;
                    width: 100%;
                    padding: 12px;
                    margin-top: 12px;
                    border-radius: 7px;
                    border: 1px solid #ddd;
                }
                button {
                    background: #2563eb;
                    color: white;
                    border: none;
                    cursor: pointer;
                }
                .message {
                    margin-top: 15px;
                    color: #2563eb;
                }
            </style>
        </head>
        <body>
            <div class="box">
                <h2>Admin Recovery</h2>

                <form method="POST">
                    <input type="hidden" name="csrf_token" value="{{ csrf }}">

                    <input
                        type="password"
                        name="recovery_key"
                        placeholder="Recovery Key"
                        required
                    >

                    <input
                        type="text"
                        name="username"
                        placeholder="Admin Username"
                        minlength="3"
                        maxlength="40"
                        required
                    >

                    <input
                        type="password"
                        name="password"
                        placeholder="New Admin Password"
                        minlength="12"
                        maxlength="128"
                        required
                    >

                    <button type="submit">Recover Admin Account</button>
                </form>

                {% if message %}
                    <p class="message">{{ message }}</p>
                {% endif %}
            </div>
        </body>
        </html>
    """, message=message, csrf=session.get("csrf_token", ""))


def money(cents):
    return f"$ {cents / 100:,.2f}"


def parse_amount(value):
    try:
        amount = Decimal(value).quantize(Decimal("0.01"))

        if amount <= 0:
            return None

        cents = int(amount * 100)

        if cents > 999999999999:
            return None

        return cents

    except (InvalidOperation, ValueError):
        return None


def valid_date(value):
    try:
        return date.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def upload_receipt(file):
    if not file or not file.filename:
        return ""

    if not allowed_file(file.filename):
        raise ValueError("Only JPG, JPEG, PNG and WEBP images are allowed.")

    original_name = secure_filename(file.filename)

    if not original_name or "." not in original_name:
        raise ValueError("Invalid file name.")

    extension = original_name.rsplit(".", 1)[1].lower()
    new_name = uuid.uuid4().hex + "." + extension

    file.save(UPLOAD_DIR / new_name)

    return new_name


def get_receipt_hash(filepath):
    try:
        with Image.open(filepath) as img:
            img = img.convert("RGB")
            return str(imagehash.phash(img))
    except Exception:
        return ""


def compare_receipt_hash(hash1, hash2):
    try:
        image1 = imagehash.hex_to_hash(str(hash1))
        image2 = imagehash.hex_to_hash(str(hash2))

        return image1 - image2

    except (ValueError, TypeError):
        return 999


def delete_receipt(filename):
    if filename:
        path = UPLOAD_DIR / filename
        if path.exists() and path.is_file():
            path.unlink()


# ==========================================
# 4. HTML TEMPLATE
# ==========================================

PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} | DailyBiz</title>

<style>
* { box-sizing:border-box; margin:0; padding:0; }

:root {
    --green:#15966b;
    --green2:#e8f7f0;
    --dark:#142b24;
    --bg:#f5f7f6;
    --white:#fff;
    --muted:#7a8982;
    --border:#e6ece8;
    --red:#d95353;
}

body {
    font-family:Arial,sans-serif;
    background:var(--bg);
    color:#24352d;
}

a { text-decoration:none; color:inherit; }

nav {
    height:68px;
    background:var(--dark);
    color:white;
    display:flex;
    align-items:center;
    justify-content:space-between;
    padding:0 5%;
}

.logo {
    font-size:23px;
    font-weight:800;
    letter-spacing:-1px;
}

.logo span { color:#4de0a8; }

.nav-right {
    display:flex;
    align-items:center;
    gap:20px;
    font-size:13px;
}

.nav-right a:hover { color:#4de0a8; }

.container {
    max-width:1120px;
    width:92%;
    margin:35px auto;
}

.heading {
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:15px;
    margin-bottom:25px;
    flex-wrap:wrap;
}

.heading h1 { font-size:28px; }

.sub {
    color:var(--muted);
    margin-top:6px;
    font-size:13px;
}

.grid {
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:17px;
    margin-bottom:24px;
}

.card {
    background:white;
    padding:23px;
    border:1px solid var(--border);
    border-radius:12px;
}

.card small {
    color:var(--muted);
    font-size:12px;
}

.card h2 {
    margin-top:12px;
    font-size:25px;
    letter-spacing:-1px;
}

.green { color:var(--green); }
.red { color:var(--red); }

.panel {
    background:white;
    padding:24px;
    border:1px solid var(--border);
    border-radius:12px;
    margin-bottom:22px;
}

.panel h2 {
    font-size:18px;
    margin-bottom:19px;
}

.btn {
    display:inline-block;
    background:var(--green);
    color:white;
    border:0;
    border-radius:7px;
    padding:11px 17px;
    font-weight:bold;
    font-size:13px;
    cursor:pointer;
}

.btn:hover { opacity:.87; }

.btn-secondary {
    background:#edf3ef;
    color:#263d32;
}

.btn-danger {
    background:#fff0f0;
    color:#c33;
}

form { margin:0; }

input,select,textarea {
    width:100%;
    padding:12px;
    border:1px solid #dce5df;
    border-radius:7px;
    margin-top:7px;
    margin-bottom:16px;
    font-size:14px;
    background:white;
}

textarea { min-height:85px; resize:vertical; }

label {
    font-size:13px;
    font-weight:bold;
}

.form-grid {
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:15px;
}

.form-grid .full { grid-column:1/-1; }

table {
    width:100%;
    border-collapse:collapse;
    font-size:13px;
}

th,td {
    padding:14px 10px;
    border-bottom:1px solid var(--border);
    text-align:left;
}

th {
    color:var(--muted);
    font-size:11px;
    text-transform:uppercase;
}

.type-income {
    color:var(--green);
    font-weight:bold;
}

.type-expense {
    color:var(--red);
    font-weight:bold;
}

.flash {
    padding:13px 16px;
    border-radius:8px;
    margin-bottom:16px;
    background:#e8f7f0;
    color:#16734f;
    font-size:13px;
}

.flash.error {
    background:#fff0f0;
    color:#bb3d3d;
}

.login-box {
    max-width:430px;
    margin:75px auto;
    background:white;
    padding:35px;
    border-radius:15px;
    border:1px solid var(--border);
}

.login-box h1 { margin-bottom:8px; }

.login-box p {
    color:var(--muted);
    margin-bottom:25px;
    font-size:13px;
}

.actions {
    display:flex;
    gap:7px;
    flex-wrap:wrap;
}

.actions form { display:inline; }

.actions .btn { padding:7px 10px; }

.badge {
    background:var(--green2);
    color:var(--green);
    padding:5px 9px;
    border-radius:20px;
    font-size:11px;
}

.muted { color:var(--muted); }

.filters {
    display:grid;
    grid-template-columns:1fr 1fr 1fr auto;
    gap:10px;
    align-items:end;
}

.filters input,.filters select { margin-bottom:0; }

.receipt {
    max-width:90px;
    max-height:70px;
    border-radius:5px;
}

.empty {
    padding:35px;
    text-align:center;
    color:var(--muted);
}

footer {
    text-align:center;
    padding:30px;
    color:var(--muted);
    font-size:12px;
}

@media(max-width:700px) {
    .grid { grid-template-columns:1fr; }
    .form-grid { grid-template-columns:1fr; }
    .form-grid .full { grid-column:auto; }
    .filters { grid-template-columns:1fr 1fr; }
    .container { margin:23px auto; }
    .panel { padding:17px; overflow-x:auto; }
    .heading h1 { font-size:23px; }
    nav { padding:0 4%; }
    .nav-right { gap:10px; }
}
</style>
</head>

<body>

<nav>
    <a href="{{ url_for('home') }}" class="logo">
        Daily<span>Biz.</span>
    </a>

    {% if user %}
    <div class="nav-right">
        <span>{{ user['business_name'] }}</span>
        <a href="{{ url_for('home') }}">Home</a>
        {% if user['role'] == 'admin' %}
        <a href="{{ url_for('admin') }}">Accounts</a>
        {% else %}
        <a href="{{ url_for('analytics') }}">Analytics</a>
        {% endif %}
        <a href="{{ url_for('logout') }}">Logout</a>
    </div>
    {% endif %}
</nav>

<div class="container">

{% with messages = get_flashed_messages(with_categories=true) %}
{% for category,message in messages %}
<div class="flash {% if category == 'error' %}error{% endif %}">
    {{ message }}
</div>
{% endfor %}
{% endwith %}


{% if page == 'login' %}

<div class="login-box">
    <h1>Welcome back.</h1>
    <p>Sign in to manage your business records.</p>

    <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf }}">

        <label>Username</label>
        <input name="username" required autocomplete="username">

        <label>Password</label>
        <input type="password" name="password"
               required autocomplete="current-password">

        <button class="btn" style="width:100%">
            Sign In
        </button>
    </form>
</div>


{% elif page == 'dashboard' %}

<div class="heading">
    <div>
        <h1>Business Overview</h1>
        <p class="sub">Welcome, {{ user['business_name'] }}.</p>
    </div>
    <span class="badge">Business Account</span>
</div>


<div class="panel">
    <h2>Today</h2>
    <div class="grid">
        <div class="card">
            <small>Today's Revenue</small>
            <h2 class="green">{{ money(today_income) }}</h2>
        </div>

        <div class="card">
            <small>Today's Expenses</small>
            <h2 class="red">{{ money(today_expense) }}</h2>
        </div>

        <div class="card">
            <small>Today's Net Profit</small>
            <h2>{{ money(today_profit) }}</h2>
        </div>
    </div>
</div>

<div class="panel">
    <h2>This Week</h2>
    <div class="grid">
        <div class="card">
            <small>Weekly Revenue</small>
            <h2 class="green">{{ money(week_income) }}</h2>
        </div>

        <div class="card">
            <small>Weekly Expenses</small>
            <h2 class="red">{{ money(week_expense) }}</h2>
        </div>

        <div class="card">
            <small>Weekly Net Profit</small>
            <h2>{{ money(week_profit) }}</h2>
        </div>
    </div>
</div>

<div class="panel">
    <h2>This Month</h2>
    <div class="grid">
        <div class="card">
            <small>Monthly Revenue</small>
            <h2 class="green">{{ money(month_income) }}</h2>
        </div>

        <div class="card">
            <small>Monthly Expenses</small>
            <h2 class="red">{{ money(month_expense) }}</h2>
        </div>

        <div class="card">
            <small>Monthly Net Profit</small>
            <h2>{{ money(month_profit) }}</h2>
        </div>
    </div>
</div>


<div class="panel">
    <h2>Quick Actions</h2>
    <div class="actions">
        <a class="btn" href="{{ url_for('add_transaction',kind='income') }}">
            + Record Revenue
        </a>

        <a class="btn btn-danger" href="{{ url_for('add_transaction',kind='expense') }}">
            + Record Expense
        </a>

        <a class="btn btn-secondary" href="{{ url_for('analytics') }}">
            📊 Analytics
        </a>

        <a class="btn btn-secondary" href="{{ url_for('history') }}">
            View History
        </a>
    </div>
</div>

<div class="panel">
    <h2>Recent Transactions</h2>

    {% if records %}
    <table>
        <tr>
            <th>Date</th>
            <th>Type</th>
            <th>Category</th>
            <th>Amount</th>
        </tr>

        {% for r in records %}
        <tr>
            <td>{{ r['txn_date'] }}</td>
            <td>
                <span class="{% if r['type']=='income' %}type-income{% else %}type-expense{% endif %}">
                    {{ r['type']|title }}
                </span>
            </td>
            <td>{{ r['category'] }}</td>
            <td>{{ money(r['amount_cents']) }}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <div class="empty">No transactions yet. Record your first transaction!</div>
    {% endif %}
</div>

{% elif page == 'analytics' %}

<div class="heading">
    <div>
        <h1>Business Analytics</h1>
        <p class="sub">Revenue and expenses for a date range.</p>
    </div>
    <a class="btn btn-secondary" href="{{ url_for('home') }}">Dashboard</a>
</div>

<div class="panel">
    <form method="GET" action="{{ url_for('analytics') }}"
          class="filters" style="grid-template-columns:1fr 1fr auto;">
        <div>
            <label>Start Date</label>
            <input type="date" name="start" value="{{ start_date }}">
        </div>

        <div>
            <label>End Date</label>
            <input type="date" name="end" value="{{ end_date }}">
        </div>

        <button class="btn" type="submit">Apply</button>
    </form>
</div>

<div class="grid">
    <div class="card">
        <small>Total Revenue</small>
        <h2 class="green">{{ money(total_income) }}</h2>
    </div>

    <div class="card">
        <small>Total Expenses</small>
        <h2 class="red">{{ money(total_expense) }}</h2>
    </div>

    <div class="card">
        <small>Net Profit</small>
        <h2>{{ money(total_income - total_expense) }}</h2>
    </div>
</div>

<div class="panel">
    <h2>Daily Performance</h2>

    {% if daily_records %}
    <table>
        <tr>
            <th>Date</th>
            <th>Revenue</th>
            <th>Expenses</th>
            <th>Profit</th>
        </tr>

        {% for day in daily_records %}
        <tr>
            <td>{{ day.date }}</td>
            <td class="type-income">{{ money(day.income) }}</td>
            <td class="type-expense">{{ money(day.expense) }}</td>
            <td>{{ money(day.income - day.expense) }}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <div class="empty">No transactions found for this period.</div>
    {% endif %}
</div>

{% elif page == 'transaction' %}

<div class="heading">
    <div>
        <h1>{{ heading }}</h1>
        <p class="sub">Enter your business transaction details.</p>
    </div>
    <a class="btn btn-secondary" href="{{ url_for('history') }}">Back</a>
</div>

<div class="panel">
<form method="POST" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{{ csrf }}">

    <div class="form-grid">

        <div>
            <label>Transaction Type</label>
            <select name="type" required>
                <option value="income" {% if kind=='income' %}selected{% endif %}>Revenue</option>
                <option value="expense" {% if kind=='expense' %}selected{% endif %}>Expense</option>
            </select>
        </div>

        <div>
            <label>Category</label>
            <select name="category" required>
                {% for c in categories %}
                <option value="{{ c }}" {% if category==c %}selected{% endif %}>
                    {{ c }}
                </option>
                {% endfor %}
            </select>
        </div>

        <div>
            <label>Amount ($)</label>
            <input type="number" name="amount" min="0.01"
                   step="0.01" required value="{{ amount }}">
        </div>

        <div>
            <label>Date</label>
            <input type="date" name="txn_date" required value="{{ txn_date }}">
        </div>

        <div class="full">
            <label>Description</label>
            <textarea name="description"
                      placeholder="Add transaction details...">{{ description }}</textarea>
        </div>

        <div class="full">
            <label>Receipt Image (Optional)</label>
            <input type="file" name="receipt" accept=".jpg,.jpeg,.png,.webp,image/*">
            <small class="muted">Maximum file size: 5 MB. JPG, PNG and WEBP.</small>
            {% if old_receipt %}
            <p style="margin-top:10px">
                Existing receipt: <a class="green" href="{{ url_for('receipt',transaction_id=transaction_id) }}" target="_blank">View receipt</a>
            </p>
            {% endif %}
        </div>

    </div>

    <button class="btn">{{ button_text }}</button>
</form>
</div>


{% elif page == 'history' %}

<div class="heading">
    <div>
        <h1>Transaction History</h1>
        <p class="sub">Review and manage your business transactions.</p>
    </div>
    <a href="{{ url_for('home') }}" class="btn btn-secondary">Dashboard</a>
</div>

<div class="panel">
<form method="GET" class="filters">

    <div>
        <label>Search</label>
        <input
            type="search"
            name="search"
            placeholder="Search description or category"
            value="{{ search }}">
    </div>

    <div>
        <label>Start Date</label>
        <input type="date" name="start" value="{{ start }}">
    </div>

    <div>
        <label>End Date</label>
        <input type="date" name="end" value="{{ end }}">
    </div>

    <div>
        <label>Transaction Type</label>
        <select name="kind">
            <option value="all" {% if kind == "all" %}selected{% endif %}>All</option>
            <option value="income" {% if kind == "income" %}selected{% endif %}>Revenue</option>
            <option value="expense" {% if kind == "expense" %}selected{% endif %}>Expense</option>
        </select>
    </div>

    <div>
        <label>Category</label>
        <input
            type="text"
            name="category"
            placeholder="e.g. Rent"
            value="{{ category }}">
    </div>

    <button class="btn">Filter</button>

</form>
<div class="panel" style="margin-top:16px;">

    <h3>Search by Receipt Photo</h3>

    <p class="muted">
        Upload a receipt photo to find similar transactions.
    </p>

    <form
        method="POST"
        action="{{ url_for('photo_search') }}"
        enctype="multipart/form-data"
    >

        <input type="hidden" name="csrf_token" value="{{ csrf }}">

        <input
            type="file"
            name="photo"
            accept="image/jpeg,image/png,image/webp"
            required
        >

        <button class="btn" type="submit">
            Search Receipt
        </button>

    </form>

</div>
</div>

<div class="panel">
    <h2>Records ({{ records|length }})</h2>

    {% if records %}
    <table>
        <tr>
            <th>Date</th>
            <th>Type</th>
            <th>Category</th>
            <th>Amount</th>
            <th>Receipt</th>
            <th>Actions</th>
        </tr>

        {% for r in records %}
        <tr>
            <td>{{ r['txn_date'] }}</td>
            <td>
                <span class="{% if r['type']=='income' %}type-income{% else %}type-expense{% endif %}">
                    {{ r['type']|title }}
                </span>
            </td>
            <td>
                {{ r['category'] }}

                {% if r['description'] %}
                <br><small class="muted">{{ r['description'] }}</small>
                {% endif %}

                {% if photo_search|default(false) %}
                <br>
                <small class="green">
                    Photo Match: {{ r['similarity'] }}%
                </small>
                {% endif %}
            </td>
            <td>{{ money(r['amount_cents']) }}</td>
            <td>
                {% if r['receipt'] %}
                <a class="green" href="{{ url_for('receipt',transaction_id=r['id']) }}" target="_blank">View</a>
                {% else %}
                -
                {% endif %}
            </td>
            <td>
                <div class="actions">
                    <a class="btn btn-secondary"
                       href="{{ url_for('edit_transaction',transaction_id=r['id']) }}">
                       Edit
                    </a>

                    <form method="POST"
                          action="{{ url_for('delete_transaction',transaction_id=r['id']) }}"
                          onsubmit="return confirm('Delete this transaction?')">
                        <input type="hidden" name="csrf_token" value="{{ csrf }}">
                        <button class="btn btn-danger">Delete</button>
                    </form>
                </div>
            </td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <div class="empty">No matching transactions found.</div>
    {% endif %}
</div>


{% elif page == 'admin' %}

<div class="heading">
    <div>
        <h1>Customer Accounts</h1>
        <p class="sub">Create and manage business accounts.</p>
    </div>
</div>

<div class="panel">
    <h2>Create New Customer Account</h2>

    <form method="POST" action="{{ url_for('create_user') }}">
        <input type="hidden" name="csrf_token" value="{{ csrf }}">

        <div class="form-grid">
            <div>
                <label>Business Name</label>
                <input name="business_name" required maxlength="80">
            </div>

            <div>
                <label>Username</label>
                <input name="username" required maxlength="40">
            </div>

            <div>
                <label>Temporary Password</label>
                <input name="password" type="password" required minlength="8">
            </div>
        </div>

        <button class="btn">Create Account</button>
    </form>
</div>

<div class="panel">
    <h2>Existing Accounts</h2>

    {% if accounts %}
    <table>
        <tr>
            <th>Business</th>
            <th>Username</th>
            <th>Status</th>
            <th>Created</th>
            <th>Action</th>
        </tr>

        {% for u in accounts %}
        <tr>
            <td>{{ u['business_name'] }}</td>
            <td>{{ u['username'] }}</td>
            <td>
                {% if u['active'] %}
                    <span class="type-income">Active</span>
                {% else %}
                    <span class="type-expense">Disabled</span>
                {% endif %}
            </td>
            <td>{{ u['created_at'] }}</td>
            <td>
                {% if u['active'] %}
                    <form method="POST"
                        action="{{ url_for('deactivate_user', user_id=u['id']) }}"
                        onsubmit="return confirm('Are you sure you want to deactivate this customer?');">
                        <input type="hidden" name="csrf_token" value="{{ csrf }}">
                        <button class="btn btn-danger" type="submit">Deactivate</button>
                    </form>
                {% else %}
                    <form method="POST"
                        action="{{ url_for('reactivate_user', user_id=u['id']) }}"
                        onsubmit="return confirm('Are you sure you want to reactivate this customer?');">
                        <input type="hidden" name="csrf_token" value="{{ csrf }}">
                        <button class="btn btn-secondary" type="submit">Reactivate</button>
                    </form>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <div class="empty">No customer accounts yet.</div>
    {% endif %}

</div>

{% endif %}

</div>

<footer>
    DailyBiz · Sales & Expense Management
</footer>

</body>
</html>
"""


def page(title, page_name, user=None, **data):
    return render_template_string(
        PAGE,
        title=title,
        page=page_name,
        user=user,
        csrf=session.get("csrf_token"),
        money=money,
        **data
    )


# ==========================================
# 5. LOGIN AND LOGOUT
# ==========================================

@app.route("/", methods=["GET", "POST"])
def login():

    if current_user():
        return redirect(url_for("home"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = connect_db()

        user = db.execute(
            "SELECT * FROM users WHERE username = ? AND active = 1",
            (username,)
        ).fetchone()

        db.close()

        if user and check_password_hash(user["password_hash"], password):

            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_hex(32)

            flash("Welcome back!")

            return redirect(url_for("home"))

        flash("Incorrect username or password.", "error")

    return page("Login", "login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ==========================================
# 6. DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required
def home():

    user = current_user()

    if user["role"] == "admin":
        return redirect(url_for("admin"))

    db = connect_db()

    today = date.today()

    # Monday to Sunday
    week_start = today - timedelta(days=today.weekday())

    # First day of this month
    month_start = today.replace(day=1)

    records = db.execute("""
        SELECT * FROM transactions
        WHERE user_id = ?
        ORDER BY txn_date DESC, id DESC
        LIMIT 8
    """, (user["id"],)).fetchall()

    def total(kind, start_date, end_date):

        result = db.execute("""
            SELECT COALESCE(SUM(amount_cents), 0) AS total
            FROM transactions
            WHERE user_id = ?
            AND type = ?
            AND txn_date >= ?
            AND txn_date <= ?
        """, (
            user["id"],
            kind,
            start_date.isoformat(),
            end_date.isoformat()
        )).fetchone()

        return result["total"]

    today_income = total("income", today, today)
    today_expense = total("expense", today, today)
    today_profit = today_income - today_expense

    week_income = total("income", week_start, today)
    week_expense = total("expense", week_start, today)
    week_profit = week_income - week_expense

    month_income = total("income", month_start, today)
    month_expense = total("expense", month_start, today)
    month_profit = month_income - month_expense

    db.close()

    return page(
        "Dashboard", "dashboard", user,

        records=records,

        today_income=today_income,
        today_expense=today_expense,
        today_profit=today_profit,

        week_income=week_income,
        week_expense=week_expense,
        week_profit=week_profit,

        month_income=month_income,
        month_expense=month_expense,
        month_profit=month_profit
    )


# ==========================================
# 7. ANALYTICS
# ==========================================

@app.route("/analytics")
@owner_required
def analytics():
    user = current_user()

    today = date.today()
    default_start = today.replace(day=1)

    start_date = request.args.get("start", default_start.isoformat())
    end_date = request.args.get("end", today.isoformat())

    if not valid_date(start_date) or not valid_date(end_date):
        abort(400)

    if start_date > end_date:
        abort(400)

    conn = connect_db()

    summary = conn.execute("""
        SELECT
            COALESCE(SUM(CASE WHEN type = 'income'
                THEN amount_cents ELSE 0 END), 0) AS income,
            COALESCE(SUM(CASE WHEN type = 'expense'
                THEN amount_cents ELSE 0 END), 0) AS expense
        FROM transactions
        WHERE user_id = ?
        AND txn_date BETWEEN ? AND ?
    """, (user["id"], start_date, end_date)).fetchone()

    rows = conn.execute("""
        SELECT
            txn_date,
            SUM(CASE WHEN type = 'income'
                THEN amount_cents ELSE 0 END) AS income,
            SUM(CASE WHEN type = 'expense'
                THEN amount_cents ELSE 0 END) AS expense
        FROM transactions
        WHERE user_id = ?
        AND txn_date BETWEEN ? AND ?
        GROUP BY txn_date
        ORDER BY txn_date DESC
    """, (user["id"], start_date, end_date)).fetchall()

    conn.close()

    daily_records = [
        {
            "date": row["txn_date"],
            "income": row["income"],
            "expense": row["expense"]
        }
        for row in rows
    ]

    return page(
        "Analytics", "analytics", user,
        start_date=start_date,
        end_date=end_date,
        total_income=summary["income"],
        total_expense=summary["expense"],
        daily_records=daily_records
    )


# ==========================================
# 7B. ADD TRANSACTION
# ==========================================

@app.route("/transaction/add/<kind>", methods=["GET", "POST"])
@owner_required
def add_transaction(kind):

    if kind not in ("income", "expense"):
        abort(404)

    user = current_user()

    categories = (
        ["Sales", "Other Income"]
        if kind == "income"
        else ["Food & Ingredients", "Rent", "Salary",
              "Utilities", "Equipment", "Transport", "Other Expense"]
    )

    if request.method == "POST":

        transaction_type = request.form.get("type")
        category = request.form.get("category", "").strip()
        amount = parse_amount(request.form.get("amount", ""))
        txn_date = valid_date(request.form.get("txn_date", ""))
        description = request.form.get("description", "").strip()

        if transaction_type not in ("income", "expense"):
            flash("Invalid transaction type.", "error")
            return redirect(url_for("add_transaction", kind=kind))

        if not category or len(category) > 60:
            flash("Please enter a valid category.", "error")
            return redirect(url_for("add_transaction", kind=kind))

        if amount is None or txn_date is None:
            flash("Please enter a valid amount and date.", "error")
            return redirect(url_for("add_transaction", kind=kind))

        if len(description) > 500:
            flash("Description is too long.", "error")
            return redirect(url_for("add_transaction", kind=kind))

        try:
            receipt = upload_receipt(request.files.get("receipt"))
        except ValueError as error:
            flash(str(error), "error")
            return redirect(url_for("add_transaction", kind=kind))

        receipt_hash = ""

        if receipt:
            receipt_hash = get_receipt_hash(UPLOAD_DIR / receipt)

        db = connect_db()

        db.execute("""
            INSERT INTO transactions
            (user_id, type, category, amount_cents,
             description, txn_date, receipt, receipt_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user["id"],
            transaction_type,
            category,
            amount,
            description,
            txn_date.isoformat(),
            receipt,
            receipt_hash,
            datetime.now().isoformat(timespec="seconds")
        ))

        db.commit()
        db.close()

        flash("Transaction recorded successfully!")

        return redirect(url_for("history"))

    return page(
        "Add Transaction", "transaction", user,
        heading="Record " + kind.title(),
        kind=kind,
        categories=categories,
        category="",
        amount="",
        txn_date=date.today().isoformat(),
        description="",
        old_receipt="",
        transaction_id=None,
        button_text="Save Transaction"
    )


# ==========================================
# 8. TRANSACTION HISTORY AND FILTERS
# ==========================================

@app.route("/history")
@owner_required
def history():

    user = current_user()

    start = request.args.get("start", "")
    end = request.args.get("end", "")
    kind = request.args.get("kind", "all")
    search = request.args.get("search", "").strip()
    category = request.args.get("category", "").strip()

    query = """
        SELECT * FROM transactions
        WHERE user_id = ?
    """

    params = [user["id"]]

    if start:
        if not valid_date(start):
            abort(400)
        query += " AND txn_date >= ?"
        params.append(start)

    if end:
        if not valid_date(end):
            abort(400)
        query += " AND txn_date <= ?"
        params.append(end)

    if kind in ("income", "expense"):
        query += " AND type = ?"
        params.append(kind)
    elif kind != "all":
        abort(400)

    if search:
        query += " AND (description LIKE ? OR category LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])

    if category:
        query += " AND category = ?"
        params.append(category)

    query += " ORDER BY txn_date DESC, id DESC"

    db = connect_db()
    records = db.execute(query, params).fetchall()
    db.close()

    return page(
        "History", "history", user,
        records=records,
        start=start,
        end=end,
        kind=kind,
        search=search,
        category=category
    )


@app.route("/photo-search", methods=["POST"])
@owner_required
def photo_search():

    user = current_user()

    photo = request.files.get("photo")

    if not photo or not photo.filename:
        flash("Please upload a photo.", "error")
        return redirect(url_for("history"))

    if not allowed_file(photo.filename):
        flash("Only JPG, JPEG, PNG and WEBP images are allowed.", "error")
        return redirect(url_for("history"))

    try:
        with Image.open(photo.stream) as img:
            img = img.convert("RGB")
            uploaded_hash = imagehash.phash(img)

    except Exception:
        flash("Invalid image file.", "error")
        return redirect(url_for("history"))

    db = connect_db()

    records = db.execute("""
        SELECT *
        FROM transactions
        WHERE user_id = ?
        AND receipt_hash != ''
    """, (user["id"],)).fetchall()

    db.close()

    matches = []

    for record in records:

        distance = compare_receipt_hash(
            str(uploaded_hash),
            record["receipt_hash"]
        )

        if distance <= 8:
            matches.append((distance, record))

    matches.sort(key=lambda item: item[0])

    matched_records = []

    for distance, record in matches:
        record_data = dict(record)
        record_data["similarity"] = round((64 - distance) / 64 * 100, 1)
        matched_records.append(record_data)

    if not matched_records:
        flash("No similar receipt found.", "error")

    return page(
        "History", "history", user,
        records=matched_records,
        start="",
        end="",
        kind="all",
        search="",
        category="",
        photo_search=True
    )


# ==========================================
# 9. EDIT TRANSACTION
# ==========================================

@app.route("/transaction/edit/<int:transaction_id>",
           methods=["GET", "POST"])
@owner_required
def edit_transaction(transaction_id):

    user = current_user()
    db = connect_db()

    record = db.execute("""
        SELECT * FROM transactions
        WHERE id = ? AND user_id = ?
    """, (transaction_id, user["id"])).fetchone()

    if not record:
        db.close()
        abort(404)

    categories = (
        ["Sales", "Other Income"]
        if record["type"] == "income"
        else ["Food & Ingredients", "Rent", "Salary",
              "Utilities", "Equipment", "Transport", "Other Expense"]
    )

    if request.method == "POST":

        kind = request.form.get("type")
        category = request.form.get("category", "").strip()
        amount = parse_amount(request.form.get("amount", ""))
        txn_date = valid_date(request.form.get("txn_date", ""))
        description = request.form.get("description", "").strip()

        if (
            kind not in ("income", "expense")
            or not category
            or len(category) > 60
            or amount is None
            or txn_date is None
            or len(description) > 500
        ):
            db.close()
            flash("Please check your transaction details.", "error")
            return redirect(url_for(
                "edit_transaction", transaction_id=transaction_id
            ))

        receipt = record["receipt"]
        receipt_hash = record["receipt_hash"]

        try:
            new_receipt = upload_receipt(request.files.get("receipt"))
        except ValueError as error:
            db.close()
            flash(str(error), "error")
            return redirect(url_for(
                "edit_transaction", transaction_id=transaction_id
            ))

        if new_receipt:
            delete_receipt(receipt)
            receipt = new_receipt
            receipt_hash = get_receipt_hash(UPLOAD_DIR / new_receipt)

        db.execute("""
            UPDATE transactions
            SET type=?, category=?, amount_cents=?,
                description=?, txn_date=?, receipt=?, receipt_hash=?
            WHERE id=? AND user_id=?
        """, (
            kind, category, amount,
            description, txn_date.isoformat(),
            receipt, receipt_hash,
            transaction_id, user["id"]
        ))

        db.commit()
        db.close()

        flash("Transaction updated successfully!")
        return redirect(url_for("history"))

    db.close()

    return page(
        "Edit Transaction", "transaction", user,
        heading="Edit Transaction",
        kind=record["type"],
        categories=categories,
        category=record["category"],
        amount=f"{record['amount_cents']/100:.2f}",
        txn_date=record["txn_date"],
        description=record["description"],
        old_receipt=record["receipt"],
        transaction_id=transaction_id,
        button_text="Save Changes"
    )


# ==========================================
# 10. DELETE TRANSACTION
# ==========================================

@app.route("/transaction/delete/<int:transaction_id>",
           methods=["POST"])
@owner_required
def delete_transaction(transaction_id):

    user = current_user()

    db = connect_db()

    record = db.execute("""
        SELECT receipt FROM transactions
        WHERE id=? AND user_id=?
    """, (transaction_id, user["id"])).fetchone()

    if not record:
        db.close()
        abort(404)

    db.execute("""
        DELETE FROM transactions
        WHERE id=? AND user_id=?
    """, (transaction_id, user["id"]))

    db.commit()
    db.close()

    delete_receipt(record["receipt"])

    flash("Transaction deleted.")

    return redirect(url_for("history"))


# ==========================================
# 11. RECEIPT VIEW
# ==========================================

@app.route("/receipt/<int:transaction_id>")
@owner_required
def receipt(transaction_id):

    user = current_user()

    db = connect_db()

    record = db.execute("""
        SELECT receipt FROM transactions
        WHERE id=? AND user_id=?
    """, (transaction_id, user["id"])).fetchone()

    db.close()

    if not record or not record["receipt"]:
        abort(404)

    return send_from_directory(
        UPLOAD_DIR,
        record["receipt"],
        as_attachment=False
    )


# ==========================================
# 12. ADMIN: CUSTOMER ACCOUNTS
# ==========================================

@app.route("/admin")
@admin_required
def admin():

    user = current_user()

    db = connect_db()

    accounts = db.execute("""
        SELECT * FROM users
        WHERE role='owner'
        ORDER BY id DESC
    """).fetchall()

    db.close()

    return page(
        "Customer Accounts", "admin", user,
        accounts=accounts
    )


@app.route("/admin/create-user", methods=["POST"])
@admin_required
def create_user():

    business_name = request.form.get("business_name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if (
        not business_name
        or len(business_name) > 80
        or not USERNAME_RE.fullmatch(username)
        or len(password) < 8
        or len(password) > 128
    ):
        flash(
            "Check business name, username (3-40 characters) "
            "and password (8-128 characters).",
            "error"
        )
        return redirect(url_for("admin"))

    db = connect_db()

    try:
        db.execute("""
            INSERT INTO users
            (username, password_hash, business_name, role,
             active, created_at)
            VALUES (?, ?, ?, 'owner', 1, ?)
        """, (
            username,
            generate_password_hash(password),
            business_name,
            datetime.now().strftime("%Y-%m-%d %H:%M")
        ))

        db.commit()

        flash("Customer account created successfully!")

    except sqlite3.IntegrityError:
        flash("That username already exists.", "error")

    finally:
        db.close()

    return redirect(url_for("admin"))


def set_customer_active(user_id, active):
    db = connect_db()

    try:
        customer = db.execute("""
            SELECT id FROM users
            WHERE id = ? AND role = 'owner'
        """, (user_id,)).fetchone()

        if not customer:
            flash("Customer account not found.", "error")
            return

        db.execute("""
            UPDATE users
            SET active = ?
            WHERE id = ? AND role = 'owner'
        """, (1 if active else 0, user_id))

        db.commit()

        flash(
            "Customer account reactivated successfully!"
            if active else
            "Customer account deactivated successfully!"
        )

    finally:
        db.close()


@app.route("/admin/deactivate-user/<int:user_id>", methods=["POST"])
@admin_required
def deactivate_user(user_id):
    set_customer_active(user_id, False)
    return redirect(url_for("admin"))


@app.route("/admin/reactivate-user/<int:user_id>", methods=["POST"])
@admin_required
def reactivate_user(user_id):
    set_customer_active(user_id, True)
    return redirect(url_for("admin"))


# ==========================================
# 13. CREATE FIRST ADMIN (command line)
# ==========================================

def create_admin():

    print("\n=== DailyBiz Admin Setup ===")

    username = input("Admin username: ").strip()
    password = getpass.getpass("Admin password (12-128 characters): ")

    ok, message = upsert_admin(username, password)
    print("\n" + message)


# ==========================================
# 14. RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        create_admin()

    else:
        # Debug mode only when you ask for it: set FLASK_DEBUG=1
        app.run(debug=os.environ.get("FLASK_DEBUG") == "1")