# Alert Triage Dashboard

A working model of a fintech fraud alert queue, built by an analyst who worked one for 2.5 years.

Every triage queue runs the same loop: alerts arrive faster than they can be worked, the analyst decides what to open first, investigates on incomplete evidence, commits to a verdict, and documents it so the decision can be defended later. This project implements that loop end to end — transaction simulation, independent rule evaluation, a severity-ordered queue, and Suspend / Approve / Escalate dispositions that persist.

The detection logic isn't invented. At Remitly (via Sutherland) on the Customer Protection team, I triaged live remittance fraud alerts under SLA: high-risk corridors, money-mule patterns, account takeovers, velocity abuse, PEP/OFAC screening — and the call to hold a transfer or let the money reach the recipient. The rules in this codebase are those rules. Building them as software forced implicit decisions to become explicit: what makes a signal High rather than Medium, what states an alert may legally move between, and what a closed alert must carry as evidence.

It began as my CS50x final project. The code in this repo is the v2 refactor, which corrected a severity distribution that made the queue useless, moved alert IDs into the database, and closed a set of security holes.

**Video demo:** https://www.youtube.com/watch?v=ay6bLBLlhBU — this shows the **original CS50x submission**, not the code in this repo. The current code is v2; see [The v2 Refactor](#the-v2-refactor) for what changed.

## What This Demonstrates

**Prioritization that carries information.** The queue orders High → Medium → Low, newest first within each tier — how an analyst actually works it. v1 got this wrong: 93% of alerts were High, which is the same as having no severity model at all. Diagnosing that (a rule cascade plus a biased data generator) and correcting it to a realistic ~29% / 56% / 15% split is the core engineering work here.

**Detection and correlation as separate stages.** Every rule evaluates independently against a transaction. The highest-severity hit becomes the primary alert; the others are surfaced as correlated signals, because three detections firing on one transaction is stronger evidence than any single one. The original `if/elif` cascade short-circuited on the first match and silently discarded the rest.

**Judgment on incomplete information.** Alerts are dispositioned on the evidence available, not on certainty. The verdict is committed and recorded, mirroring real triage: make the call and move to the next alert.

**Documentation and evidence integrity.** Alert IDs are database-assigned via `AUTOINCREMENT` and never recycled, because an ID gets quoted in escalations and case notes and must stay unambiguous. Timestamps are UTC — a SOC correlates events across regions on one clock. Every disposition and state change persists; the queue exports to CSV.

**Security hygiene on state-changing endpoints.** Every mutating route (`/generate`, `/triage`, `/clear`) is POST-only with the `action` parameter validated against an allowlist; unknown actions return HTTP 400 instead of being written to the database. Export stays GET because a read is a read. Debug mode is opt-in via environment variable.

## How It Works

Each click of **Generate** simulates 50 remittance transactions. Every transaction is evaluated against all detection rules:

| Rule | Severity | Origin / Description |
|---|---|---|
| High-risk corridor + high amount | High | Limit-testing behavior in high-exposure corridors |
| High-risk corridor + elevated amount | Medium | Worth review, not an emergency |
| Gender mismatch on verification call | High | Classic account-takeover indicator |
| PEP or OFAC match | High | Screening hit — rare, always High |
| Money mule pattern + stolen info | High | Receiver fits a known mule profile |
| Velocity check failed | Medium | Transaction burst in a short window |
| Brute force / account takeover | High | Credential stuffing preceding the transaction |
| First transaction to a new recipient | Low | Common, usually benign |

Roughly 64% of simulated transactions raise an alert, and about a third of those carry correlated signals. All thresholds and probabilities are named constants at the top of `app.py`, so the queue can be re-tuned without touching the engine.

All data is synthetic. Simulated IPs come from the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so demo data can never point at a real host.

## The v2 Refactor

The original submission worked but carried first-version flaws:

| | v1 | v2 |
|---|---|---|
| **Severity distribution** | 93% High / 7% Medium / 0% Low | ~29% High / 56% Medium / 15% Low (measured over 20,000 simulations) |
| **Rule evaluation** | `if/elif` cascade — first match wins, rest discarded | Independent evaluation + correlated signals |
| **Alert IDs** | `random.randint(1000, 9999)` — ~50% collision odds by 118 alerts, and a collision crashes the insert | `INTEGER PRIMARY KEY AUTOINCREMENT` — unique, never reused |
| **State changes** | GET links — triggerable by crawlers and prefetching | POST-only with allowlisted `action` parameter |
| **Config** | `debug=True` by default, no secret key, unused dependency | Debug opt-in, secret key from environment, dead dependency removed |
| **Writes** | Connect / insert / commit / close per row | Single connection, one `executemany` + commit |

Every change, the reasoning behind it, and the known limitations are documented in `TECHNICAL_CHANGES.md`.

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Database | SQLite |
| Templates | Jinja2 |
| Frontend | Bootstrap 5, Chart.js |

## How to Run

```bash
git clone https://github.com/angelrbolivar/angelrbolivar-soc-portfolio.git
cd angelrbolivar-soc-portfolio/alert-triage-dashboard

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` and click **Generate alerts** to populate the queue.

- The SQLite database is created automatically on first run and generated at runtime — don't commit it.
- Upgrading from v1: delete the old database file first, the schema changed.
- Debug mode is off by default. Enable explicitly: `FLASK_DEBUG=1 python app.py`.

## Screenshots

<!-- ![Triage queue — severity-ordered, with correlated signals](screenshots/triage-queue.png) -->
<!-- ![Severity distribution and alerts by rule type](screenshots/charts.png) -->
<!-- ![Disposition applied — Suspend / Approve / Escalate](screenshots/disposition.png) -->

## Known Limitations

- **No CSRF tokens.** Reasonable for a local, single-user, no-auth simulator; Flask-WTF is the next step if it ever becomes multi-user.
- **No authentication, by design.** The subject is the triage workflow, not access control.
- **SQLite + the Flask dev server.** A simulation-scale choice, not a deployment story.
- **Stochastic rules stand in for real telemetry.** Production velocity checks evaluate against actual transaction history, not a probability.

Full detail in `TECHNICAL_CHANGES.md`, section 7.

## Roadmap

- pytest suite for `evaluate_rules()` and severity selection, using `random.seed()` for deterministic tests
- CSRF protection via Flask-WTF
- Basic authentication if the tool becomes multi-user

## AI Assistance Disclosure

The original version was built with help from Grok (xAI) for code structure, debugging, and the CSV export. The v2 refactor was done with Claude (Anthropic): independent rule evaluation, database-assigned IDs, POST-only routes, and security hygiene. The fraud rules, the triage logic, and the design decisions come from my own fraud operations experience. I reviewed and tested everything myself, and `TECHNICAL_CHANGES.md` documents exactly what changed and why.

## Author

**Angel Alfonso Rodriguez Bolivar** — Barranquilla, Colombia
Fraud & risk operations → security operations. CompTIA Security+ (SY0-701).
Original: March 2026 · v2 refactor: July 2026

Part of my SOC portfolio, alongside Microsoft Sentinel KQL detection rules and Tier-1 triage playbooks.
