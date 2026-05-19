"""
BlockShop Backend — Flask + Stripe
===================================
Flow:
  1. User POSTs to /checkout with their Minecraft username
  2. We create a Stripe Checkout session ($1)
  3. Stripe redirects to /success?session_id=... on payment
  4. Webhook (or success handler) generates a token, emails it, writes to SQLite
  5. Player uses /redeem <token> in-game

Environment variables (put in .env):
  STRIPE_SECRET_KEY      — sk_live_... or sk_test_...
  STRIPE_WEBHOOK_SECRET  — whsec_... (from Stripe dashboard)
  FLASK_SECRET_KEY       — any random string
  BASE_URL               — https://your-domain.com (no trailing slash)
  DB_PATH                — path to the SAME blockshop.db the plugin uses
                           (or a shared network path / copy-sync setup)
  SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS  — for sending token emails
"""

import os
import secrets
import sqlite3
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

import stripe
from flask import Flask, request, redirect, url_for, jsonify, render_template_string

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
DB_PATH  = os.environ.get("DB_PATH", "/tmp/blockshop.db")

BLOCK_PRICE_CENTS = 100   # $1.00

# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Ensure tables exist (mirrors what the plugin creates)."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS tokens (
                token       TEXT PRIMARY KEY,
                used        INTEGER NOT NULL DEFAULT 0,
                used_by     TEXT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS purchases (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                stripe_session  TEXT UNIQUE NOT NULL,
                mc_username     TEXT NOT NULL,
                email           TEXT NOT NULL,
                token           TEXT,
                paid            INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS placements (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                token       TEXT NOT NULL,
                player_uuid TEXT NOT NULL,
                player_name TEXT NOT NULL,
                world       TEXT NOT NULL,
                x           INTEGER NOT NULL,
                y           INTEGER NOT NULL,
                z           INTEGER NOT NULL,
                block_type  TEXT NOT NULL,
                placed_at   TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)

init_db()

# ── Token helpers ─────────────────────────────────────────────────────────────

def generate_token() -> str:
    """Cryptographically random 24-char uppercase token, e.g. BLOCKSHOP-A3F9-KX12-QZ77"""
    raw = secrets.token_hex(8).upper()
    return f"BLOCKSHOP-{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"

def insert_token(token: str, conn: sqlite3.Connection):
    conn.execute("INSERT OR IGNORE INTO tokens (token) VALUES (?)", (token,))

# ── Email ─────────────────────────────────────────────────────────────────────

def send_token_email(to_address: str, mc_username: str, token: str):
    try:
        body = f"""Hi {mc_username}!

Your BlockShop placement token is:

    {token}

Join the server and type:
    /redeem {token}

You'll have exactly ONE block placement in the map region. Make it count!

Thanks for your purchase,
BlockShop
"""
        msg = MIMEText(body)
        msg["Subject"] = f"Your BlockShop Token — {token}"
        msg["From"]    = os.environ["SMTP_USER"]
        msg["To"]      = to_address

        with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", 587))) as s:
            s.starttls()
            s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])
            s.send_message(msg)
    except Exception as e:
        app.logger.error(f"Email send failed: {e}")

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/checkout", methods=["POST"])
def checkout():
    mc_username = request.form.get("mc_username", "").strip()
    email       = request.form.get("email", "").strip()

    if not mc_username or not email:
        return "Missing fields", 400

    # Create Stripe Checkout session
    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{
            "price_data": {
                "currency": "usd",
                "unit_amount": BLOCK_PRICE_CENTS,
                "product_data": {
                    "name": "BlockShop — 1 Block Placement",
                    "description": f"One permanent block in the map for {mc_username}",
                },
            },
            "quantity": 1,
        }],
        mode="payment",
        customer_email=email,
        success_url=BASE_URL + "/success?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=BASE_URL + "/cancel",
        metadata={
            "mc_username": mc_username,
            "email": email,
        }
    )

    # Save pending purchase
    with get_db() as conn:
        conn.execute(
            "INSERT INTO purchases (stripe_session, mc_username, email) VALUES (?, ?, ?)",
            (session.id, mc_username, email)
        )

    return redirect(session.url)


@app.route("/success")
def success():
    """
    Stripe redirects here after payment.
    NOTE: This fires on redirect, which can be spoofed — use webhooks for
    production. This is a good fallback / dev shortcut.
    """
    session_id = request.args.get("session_id")
    if not session_id:
        return "Bad request", 400

    # Verify payment with Stripe
    session = stripe.checkout.Session.retrieve(session_id)
    if session.payment_status != "paid":
        return "Payment not completed.", 402

    _fulfill(session)
    return render_template_string("""
    <h1>✔ Payment received!</h1>
    <p>Your token has been emailed to you. Join the server and type
       <code>/redeem YOUR_TOKEN</code> to place your block.</p>
    """)


@app.route("/webhook", methods=["POST"])
def webhook():
    """
    Stripe webhook — the reliable way to fulfill orders.
    Set this URL in your Stripe dashboard → Developers → Webhooks.
    """
    payload = request.data
    sig     = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    if event["type"] == "checkout.session.completed":
        _fulfill(event["data"]["object"])

    return jsonify({"status": "ok"})


def _fulfill(session):
    """Generate + record a token, then email it. Idempotent (skips if already fulfilled)."""
    session_id  = session.id
    mc_username = session.get("metadata", {}).get("mc_username") or ""
    email       = session.get("customer_email") or session.get("metadata", {}).get("email") or ""

    with get_db() as conn:
        row = conn.execute(
            "SELECT paid, token FROM purchases WHERE stripe_session = ?", (session_id,)
        ).fetchone()

        if row and row["paid"]:
            return  # Already fulfilled — idempotent

        token = generate_token()
        insert_token(token, conn)
        conn.execute(
            "UPDATE purchases SET paid = 1, token = ? WHERE stripe_session = ?",
            (token, session_id)
        )

    send_token_email(email, mc_username, token)
    app.logger.info(f"Fulfilled: {mc_username} | token={token} | session={session_id}")


@app.route("/cancel")
def cancel():
    return render_template_string("<h1>Payment cancelled.</h1><a href='/'>Go back</a>")


# ── Admin endpoints (protect these with HTTP basic auth or IP allowlist!) ──────

@app.route("/admin/placements")
def admin_placements():
    """Quick view of all placed blocks."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM placements ORDER BY placed_at DESC LIMIT 200"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/purchases")
def admin_purchases():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM purchases ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(debug=True, port=5000)
