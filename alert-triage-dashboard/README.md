# FraudDetective — Fintech SOC Simulator

An educational SOC-style triage dashboard for remittance fraud alerts, built in Flask. All data is synthetic.

#### Video Demo: https://www.youtube.com/watch?v=ay6bLBLlhBU

*(The video shows the original CS50x submission. The code in this repo is the v2 refactor — see below.)*

## Description

Hi, my name is Angel Alfonso Rodriguez Bolivar, and this started as my final project for CS50x — the best course I have ever taken.

I spent 2.5 years at Sutherland working for Remitly on the Customer Protection team. Every day I handled fraud alerts: KYC checks, money mule patterns, account takeovers, gender-mismatch red flags, and the call to suspend an account or let the money reach the recipient. FraudDetective is that experience turned into code — a dashboard that generates realistic fraud alerts and lets you triage them the way I did on the job. It's also part of my move from fraud operations into security operations and blue-team work.

## What it does

- Simulates remittance transactions and evaluates them against the rules I actually worked: high-risk corridors, gender mismatch (an account-takeover signal), velocity, money mules, PEP/OFAC, brute force, first-time recipients
- Every rule evaluates independently; the highest-severity hit becomes the alert, and other hits on the same transaction are surfaced as correlated signals
- Triage queue sorted the way analysts work it: High first, then newest within each tier
- Suspend / Approve / Escalate actions with flash feedback — every state change is POST-only with allowlisted inputs
- Live charts (severity split, alerts by rule), UTC timestamps, CSV export
- SQLite persistence with database-assigned alert IDs that are never reused

## The v2 refactor

The original submission worked, but had first-version flaws: a rule cascade plus biased data generation made **93% of alerts High severity**, IDs were random four-digit numbers guaranteed to eventually collide, and state changes rode on GET links. The refactor fixed both the engine and the data generator — measured over 20,000 simulated transactions, the queue now lands at roughly **29% High / 56% Medium / 15% Low** — moved IDs into the database with AUTOINCREMENT, made every mutating route POST-only, and cleaned up security hygiene (debug mode opt-in, secret key set, dead dependency removed).

The full write-up of every change, the reasoning behind it, and known limitations: [TECHNICAL_CHANGES.md](TECHNICAL_CHANGES.md).

## Technologies

- Flask (Python) — backend, routes, rule engine
- SQLite — persistence
- Jinja2 — templates
- Bootstrap — layout
- Chart.js — live charts

## How to run

```
git clone <this repo>
cd fraudetective
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. The database is created automatically on first run. `fraudetective.db` is generated at runtime — don't commit it, and if you're upgrading from v1, delete the old file first (the schema changed). Debug mode is off by default; enable it explicitly with `FLASK_DEBUG=1 python app.py`.

## Files

- `app.py` — backend logic, rule engine, routes, database
- `templates/layout.html` — base template (navbar, footer, styles)
- `templates/index.html` — home page
- `templates/dashboard.html` — the SOC dashboard (charts, queue, triage forms)
- `TECHNICAL_CHANGES.md` — the v2 refactor, change by change
- `requirements.txt` — dependencies

## Known limitations

This is an educational simulation, and it says so on the dashboard. There is no authentication (by design — the point is the triage workflow, not access control), no CSRF tokens yet (next step: Flask-WTF), SQLite plus the dev server (simulation scale, not a deployment story), and stochastic rules standing in for real telemetry. Details in TECHNICAL_CHANGES.md, section 7.

## Roadmap

- A `pytest` suite for `evaluate_rules()` with seeded, deterministic tests
- CSRF protection via Flask-WTF
- Basic authentication if the tool ever becomes multi-user

## AI Assistance Disclosure

The original version was built with help from Grok (xAI) for code structure, debugging, and the CSV export. The v2 refactor was done with Claude (Anthropic): independent rule evaluation, database-assigned IDs, POST-only routes, and security hygiene. The fraud rules, the triage logic, and the design decisions come from my own 2.5 years of fraud operations experience — I reviewed and tested everything myself, and TECHNICAL_CHANGES.md documents exactly what changed and why.

## Author

Angel Alfonso Rodriguez Bolivar
Barranquilla, Colombia
Original: March 2026 · v2 refactor: July 2026
