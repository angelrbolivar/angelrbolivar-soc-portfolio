"""
FRAUDETECTIVE — Fintech SOC Simulator
=====================================
Educational simulation of a fraud-alert triage queue, modeled on real
remittance fraud operations: high-risk corridors, account-takeover (ATO)
signals, velocity abuse, money-mule patterns, and PEP/OFAC screening.

This is a training/portfolio tool. All data is synthetic. It is deliberately
not a production application and has no authentication layer.

AI Assistance Disclosure:
- Original version: built with help from Grok (xAI) for structure and debugging.
- This revision: refactored with help from Claude (Anthropic) — independent
  rule evaluation, database-managed alert IDs, POST-only state changes, and
  security/config hygiene.
The fraud rules, severities, and the triage workflow itself come from my
2.5 years of fraud operations experience at Remitly.
"""

import csv
import io
import os
import random
import sqlite3
from datetime import datetime, timezone

from flask import Flask, Response, abort, flash, redirect, render_template, url_for

app = Flask(__name__)

# Flask signs its session cookie (used here only for flash messages) with this
# key. Prefer an environment variable; the random fallback is acceptable for a
# local simulator — it just means flash messages reset when the app restarts.
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

DB_PATH = "fraudetective.db"

# ---------------------------------------------------------------------------
# Detection tuning — everything an analyst might want to adjust lives here.
# ---------------------------------------------------------------------------
COUNTRIES = ["Colombia", "Mexico", "Dominican Republic", "USA", "Spain"]

# Corridors with the highest mule/scam exposure in my remittance experience.
HIGH_RISK_CORRIDORS = {"Colombia", "Mexico", "Dominican Republic"}

AMOUNT_MIN, AMOUNT_MAX = 300, 6500  # USD per transaction
CORRIDOR_HIGH_AMOUNT = 6000    # pushed against the ceiling = limit-testing behavior
CORRIDOR_MEDIUM_AMOUNT = 2500  # elevated and worth a look, not an emergency

# Independent per-transaction probabilities for the stochastic signals.
# Tuned so the queue looks like a real one: mostly Medium/Low with a credible
# minority of High — not a wall of High severity.
P_GENDER_MISMATCH = 0.05  # caller voice vs profile mismatch on a verification call
P_PEP_OFAC = 0.02         # screening hits are rare, but always High when they fire
P_VELOCITY = 0.12         # burst of transactions in a short window
P_MULE = 0.04             # receiver fits a known money-mule pattern
P_BRUTE_FORCE = 0.05      # credential stuffing / failed logins before the transaction
P_NEW_RECIPIENT = 0.22    # first payment to a new recipient: common, usually benign

TRANSACTIONS_PER_BATCH = 50  # simulated transactions per click of "Generate"

SEVERITY_RANK = {"High": 3, "Medium": 2, "Low": 1}

# Allowlist mapping the triage URL parameter -> status stored in the DB.
# Anything not in this dict is rejected with HTTP 400: never trust raw input,
# even in a simulator.
VALID_ACTIONS = {
    "suspended": "Suspended",
    "approved": "Approved",
    "escalated": "Escalated",
}


# ---------------------------------------------------------------------------
# Synthetic data + rule engine
# ---------------------------------------------------------------------------
def generate_transaction():
    """Simulate one remittance transaction. All values are synthetic."""
    sender = random.choice(COUNTRIES)
    # A remittance moves money between two different countries.
    receiver = random.choice([c for c in COUNTRIES if c != sender])

    # IPs come from the RFC 5737 documentation ranges: they look like public
    # addresses but are reserved for examples, so synthetic data can never
    # point at a real host.
    ip = f"{random.choice(['192.0.2', '198.51.100', '203.0.113'])}.{random.randint(1, 254)}"

    # Most verification calls match the profile on record. A small minority
    # don't — that mismatch is the interesting ATO signal, so it is generated
    # as a rare event, not a coin flip.
    profile_gender = random.choice(["Male", "Female"])
    caller_gender = profile_gender
    if random.random() < P_GENDER_MISMATCH:
        caller_gender = "Female" if profile_gender == "Male" else "Male"

    return {
        "sender": sender,
        "receiver": receiver,
        "amount": random.randint(AMOUNT_MIN, AMOUNT_MAX),
        "ip": ip,
        "profile_gender": profile_gender,
        "caller_gender": caller_gender,
    }


def evaluate_rules(txn):
    """
    Run every detection rule independently and return a list of
    (rule_name, severity) tuples for the ones that fired.

    Independent evaluation matters: in a real SIEM one transaction can trip
    several detections at once, and correlation happens *after* detection.
    The old if/elif chain short-circuited on the first match, which hid
    correlated signals and skewed the whole queue toward High.
    """
    triggered = []

    # 1) Corridor risk (deterministic on the transaction data).
    if txn["sender"] in HIGH_RISK_CORRIDORS:
        if txn["amount"] >= CORRIDOR_HIGH_AMOUNT:
            # Amounts pushed against the per-transaction ceiling in a risky
            # corridor look like limit-testing.
            triggered.append(("High-risk corridor + high amount", "High"))
        elif txn["amount"] >= CORRIDOR_MEDIUM_AMOUNT:
            triggered.append(("High-risk corridor + elevated amount", "Medium"))

    # 2) Voice/profile mismatch on the verification call (deterministic).
    #    A caller who does not match the registered profile is a classic
    #    account-takeover red flag.
    if txn["profile_gender"] != txn["caller_gender"]:
        triggered.append(("Gender mismatch (account takeover suspect)", "High"))

    # 3-7) Stochastic signals standing in for checks this simulator does not
    #      model in full (screening lists, login telemetry, device history).
    if random.random() < P_PEP_OFAC:
        triggered.append(("PEP or OFAC match", "High"))
    if random.random() < P_VELOCITY:
        triggered.append(("Velocity check failed (too many transactions)", "Medium"))
    if random.random() < P_MULE:
        triggered.append(("Money mule pattern + stolen info", "High"))
    if random.random() < P_BRUTE_FORCE:
        triggered.append(("Brute-force / account takeover detected", "High"))
    if random.random() < P_NEW_RECIPIENT:
        triggered.append(("First transaction to a new recipient", "Low"))

    return triggered


def generate_alert():
    """
    Simulate one transaction, evaluate all rules against it, and build the
    alert an analyst would see — or return None when nothing fires, because
    most real transactions never alert.
    """
    txn = generate_transaction()
    triggered = evaluate_rules(txn)
    if not triggered:
        return None

    # The primary rule is the highest-severity hit; ties keep rule order.
    rule, severity = max(triggered, key=lambda t: SEVERITY_RANK[t[1]])

    details = (
        f"{txn['sender']} -> {txn['receiver']} | ${txn['amount']} | "
        f"IP: {txn['ip']} | Profile: {txn['profile_gender']}, "
        f"Caller: {txn['caller_gender']}"
    )

    # Surface the other signals that fired on the same transaction —
    # correlated detections are exactly what an analyst wants to see first.
    correlated = [name for name, _ in triggered if name != rule]
    if correlated:
        details += f" | Correlated: {', '.join(correlated)}"

    return {"rule": rule, "severity": severity, "details": details}


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
def init_db():
    """Create the alerts table on first run.

    - AUTOINCREMENT: the database assigns IDs, they are guaranteed unique,
      and IDs of deleted alerts are never reused. Alert IDs get quoted in
      escalations and case notes, so they must stay unambiguous forever.
    - NOT NULL + DEFAULT 'Open': every alert enters the queue in a known
      state, and a bad insert fails loudly instead of writing half a row.
    """
    db = sqlite3.connect(DB_PATH)
    db.execute("""CREATE TABLE IF NOT EXISTS alerts (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      rule TEXT NOT NULL,
                      severity TEXT NOT NULL,
                      status TEXT NOT NULL DEFAULT 'Open',
                      details TEXT NOT NULL,
                      timestamp TEXT NOT NULL)""")
    db.commit()
    db.close()


def get_db_connection():
    """One connection per request; rows behave like dicts (row['rule'])."""
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


init_db()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    """Triage queue, ordered like a real one: High first, then newest."""
    db = get_db_connection()
    alerts = db.execute(
        """SELECT * FROM alerts
           ORDER BY CASE severity
                        WHEN 'High' THEN 1
                        WHEN 'Medium' THEN 2
                        ELSE 3
                    END,
                    id DESC"""
    ).fetchall()
    db.close()
    return render_template("dashboard.html", alerts=[dict(row) for row in alerts])


@app.route("/generate", methods=["POST"])
def generate():
    """Simulate a batch of transactions and store whatever alerts they raise.

    POST-only because it changes state. The whole batch is written over one
    connection with a single executemany + commit, instead of reconnecting
    to the database once per insert.
    """
    # SOC convention: log in UTC so events correlate across regions.
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    rows = []
    for _ in range(TRANSACTIONS_PER_BATCH):
        alert = generate_alert()
        if alert:
            rows.append((alert["rule"], alert["severity"], alert["details"], ts))

    if rows:
        db = get_db_connection()
        # Parameterized query; id and status are filled in by the schema.
        db.executemany(
            "INSERT INTO alerts (rule, severity, details, timestamp) VALUES (?, ?, ?, ?)",
            rows,
        )
        db.commit()
        db.close()

    flash(
        f"{len(rows)} alerts raised from {TRANSACTIONS_PER_BATCH} simulated "
        f"transactions ({TRANSACTIONS_PER_BATCH - len(rows)} cleared all rules)."
    )
    return redirect(url_for("dashboard"))


@app.route("/triage/<int:alert_id>/<action>", methods=["POST"])
def triage(alert_id, action):
    """Record the analyst decision on one alert. POST-only, allowlisted."""
    if action not in VALID_ACTIONS:
        abort(400)  # unknown action: reject it, never write it to the DB

    status = VALID_ACTIONS[action]
    db = get_db_connection()
    cur = db.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    updated = cur.rowcount
    db.commit()
    db.close()

    flash(f"Alert #{alert_id} marked {status}." if updated
          else f"Alert #{alert_id} not found.")
    return redirect(url_for("dashboard"))


@app.route("/clear", methods=["POST"])
def clear():
    """Wipe the queue (simulation reset). Because of AUTOINCREMENT, the IDs
    of cleared alerts are never reused, so old references stay unambiguous."""
    db = get_db_connection()
    deleted = db.execute("DELETE FROM alerts").rowcount
    db.commit()
    db.close()
    flash(f"Cleared {deleted} alerts.")
    return redirect(url_for("dashboard"))


@app.route("/export")
def export():
    """Download the queue as CSV. Read-only, so GET is the correct method."""
    db = get_db_connection()
    alerts = db.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
    db.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Rule", "Severity", "Status", "Details", "Timestamp (UTC)"])
    for alert in alerts:
        writer.writerow([alert["id"], alert["rule"], alert["severity"],
                         alert["status"], alert["details"], alert["timestamp"]])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=fraudetective_alerts.csv"},
    )


if __name__ == "__main__":
    # Never default to debug: the Werkzeug debugger is an interactive Python
    # console in the browser — remote code execution if it is ever exposed.
    # Enable explicitly when needed:  FLASK_DEBUG=1 python app.py
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
