# FraudDetective — Technical Changes (v2 Refactor)

This document explains the refactor of FraudDetective from its original CS50x submission into a portfolio-ready version, why each change matters from a SOC and professional standpoint, and how to talk about it in interviews. The project remains what it always was: an educational simulation of a fraud-alert triage workflow, built on real remittance fraud-operations experience.

## 1. Rule engine: independent evaluation instead of a cascade

**What changed.** The old engine had two bugs that combined to break the queue. First, rules were chained with `if/elif`, so the first rule to match won and every other signal on the same transaction was silently discarded. Second — and this was the bigger cause — the data generator picked `profile_gender` and `caller_gender` as two independent coin flips, which made "gender mismatch" fire on 50% of all transactions. A signal that should be a rare account-takeover indicator was the most common event in the system. The measurable result in the old database: **93% of alerts were High, 7% Medium, 0% Low.**

The new engine simulates the transaction first, then runs every detection rule independently and collects all hits. The highest-severity hit becomes the primary rule (via a severity ranking), and any other rules that fired on the same transaction are appended to the details as correlated signals. The gender mismatch is now generated as a rare event (~5%), one Low-severity rule was added ("First transaction to a new recipient") so the Low tier actually exists, and all thresholds and probabilities live as named constants at the top of `app.py` where they can be tuned. Measured over 20,000 simulated transactions, the queue now lands at roughly **29% High, 56% Medium, 15% Low**, with about 64% of transactions raising an alert and about a third of alerts carrying correlated signals.

**Why it matters.** A queue where everything is High is a queue where severity carries no information — an analyst can't prioritize, which is the entire point of triage. Real detection pipelines evaluate rules independently and correlate afterward; the correlation itself (multiple signals on one transaction) is often the strongest indicator an analyst has. The refactor makes the simulator behave like the systems it imitates.

**In an interview.** "My first version short-circuited on the first matching rule, the way access-control logic does — but detection isn't access control. In a SIEM, detection and correlation are separate stages: every rule evaluates independently, and seeing that three signals fired on one transaction is more valuable than any single one. I also found that my synthetic data itself was biased — a 50/50 coin flip made a rare ATO signal fire on half of all traffic — so I fixed the generator, not just the engine. The severity distribution went from 93% High to roughly 30/55/15."

## 2. Alert IDs: database-assigned, never reused

**What changed.** IDs were generated with `random.randint(1000, 9999)`. With only 9,000 possible values, the birthday problem gives about a 50% chance of a duplicate by roughly 118 alerts — and because `id` is the primary key, a duplicate wouldn't just look wrong, it would raise an `IntegrityError` and crash the generate request. The schema now uses `INTEGER PRIMARY KEY AUTOINCREMENT`, the application never touches IDs, and inserts simply omit the column. `AUTOINCREMENT` specifically (rather than plain `INTEGER PRIMARY KEY`) guarantees that IDs of deleted alerts are never recycled — after clearing the queue, new alerts continue from the next number.

**Why it matters.** An alert ID is a reference that outlives the alert: it gets quoted in escalations, case notes, and audit trails. If ID 4571 can ever mean two different alerts — or mean one alert today and a different one after a purge — every reference to it becomes ambiguous. Uniqueness and non-reuse are audit requirements, and they belong in the database, not in application-level randomness.

**In an interview.** "Alert IDs are evidence references, so they have two requirements: unique forever, and never reused. I moved ID generation from application-level `random.randint` — which was a guaranteed eventual collision and crash — into the database with AUTOINCREMENT, which also means clearing the queue never recycles old IDs."

## 3. State changes are POST-only, with an allowlisted action parameter

**What changed.** Triage (Suspend / Approve / Escalate), Clear, and Generate were all plain GET links. All three now accept POST only (`methods=["POST"]`), and the dashboard buttons became small HTML forms with `method="post"`. Generate was included even though the original task listed only triage and clear — it inserts rows, so the same rule applies. Export stays GET because a download is a read. Additionally, the triage `action` URL parameter is now validated against an allowlist (`suspended`/`approved`/`escalated`); anything else returns HTTP 400 instead of being written into the status column. Destructive actions (Suspend, Clear) keep a confirmation dialog, and every action now flashes a feedback message.

**Why it matters.** HTTP semantics say GET must be safe: browsers prefetch links, crawlers follow them, and anyone can embed one in an image tag on another site. With the old design, a crawler indexing the dashboard would have triaged the entire queue, and `/triage/1234/banana` would have happily written "Banana" into the database. Method enforcement plus input allowlisting is the baseline hygiene for any endpoint that changes state — the same reasoning behind CSRF defenses, applied at the level this project operates at.

**In an interview.** "State changes were riding on GET links, which means link prefetching or a forged `<img>` tag on any page could suspend accounts — the classic CSRF-shaped mistake. I moved every mutating route to POST and allowlisted the action parameter so arbitrary strings can't reach the database. Verified with curl: GET on those routes now returns 405, and an unknown action returns 400."

## 4. Security and configuration hygiene

**What changed.** Three items. `debug=True` is no longer the default — the app runs with debug off unless `FLASK_DEBUG=1` is set in the environment. A `secret_key` is now set, read from the `SECRET_KEY` environment variable with a random fallback (acceptable for a local simulator; it only means flash messages reset on restart). And `flask_session` — the server-side session extension — was removed entirely: it was a leftover from an earlier design where alerts lived in the session, and since SQLite became the store, nothing used it. Its import, its configuration block, and the dependency are gone.

**Why it matters.** The Werkzeug debugger is an interactive Python console served over HTTP — remote code execution as a feature. It's the single most common Flask misconfiguration found in the wild, and "never on by default" is the correct posture even for toys, because toys get deployed. The secret key is what signs the session cookie; hardcoding one in a public repo would be worse than the random fallback. And dead dependencies are attack surface plus reviewer noise: removing `flask_session` shrinks both the install and the explanation.

**In an interview.** "Flask's debug mode ships an in-browser Python console, so exposing it is handing out RCE — I made it opt-in via an environment variable, which is the same pattern as any environment-based configuration. I also removed an entire session extension that a previous design had left behind: unused dependencies are just attack surface you're not looking at."

## 5. Database and code quality

**What changed.** The generate route used to open and close a database connection inside the loop — up to 30 connect/insert/commit/close cycles per click. It now builds the batch in memory and writes it with one connection and a single `executemany` + commit. Timestamps are recorded in UTC with seconds precision (the old minutes-precision local time made every alert in a batch tie on `ORDER BY timestamp`). The queue is now ordered the way an analyst works it: High first, then Medium, then Low, newest first within each tier. The schema gained `NOT NULL` constraints and a `DEFAULT 'Open'` status so malformed inserts fail loudly. The triage update checks `rowcount` so acting on a nonexistent ID says "not found" instead of silently succeeding. Dead code was removed — the dashboard contained an entire client-side `exportToCSV()` JavaScript function that no button ever called (the real export is server-side). Imports moved to the top of the file, and comments were rewritten to explain analyst-relevant reasoning ("why this rule exists," "why UTC") instead of Python syntax.

**Why it matters.** Batched writes are the difference between "I made it work" and "I understand what the database is doing" — a per-row connect/commit cycle is the classic beginner tell. UTC is a SOC convention with a concrete reason: alerts from different regions must correlate on a single clock, and Barranquilla, Seattle, and Madrid don't share one. Severity-first ordering encodes the actual triage discipline: you work the Highs before the Lows. And a portfolio repo containing a large unused function tells a reviewer the author doesn't read their own code.

**In an interview.** "Small things, but they're the things a reviewer checks: one connection and one commit per batch instead of thirty, UTC timestamps because a SOC correlates events across time zones on one clock, and the queue sorts High-first because that's how triage actually works. I also deleted a dead export function — unused code in a portfolio repo is a red flag I didn't want to carry."

## 6. Small realism touches

A few one-to-three-line changes that raise credibility. Synthetic IPs now come from the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) — they look like public addresses but are reserved for examples, so demo data can never point at a real host; the old 192.168.x.x addresses were private ranges, which makes no sense for customer traffic. Sender and receiver countries are now always different, because a remittance is by definition cross-border. The empty queue shows an instructive message instead of a bare table. The generate feedback reports "32 alerts raised from 50 simulated transactions (18 cleared all rules)," which quietly teaches the concept of an alert rate. And the footer line claiming "This is a real SOC dashboard" was replaced with the honest version: "Educational SOC simulation — all data is synthetic." For a security portfolio, precise claims are part of the craft.

## 7. Known limitations (say these before the interviewer does)

The POST forms have no CSRF tokens — for a local, single-user, no-auth simulator that's a reasonable scope decision, but the honest framing is "the next step would be Flask-WTF CSRF protection if this ever became multi-user." There is no authentication by design; the point of the project is the triage workflow, not access control. SQLite plus the Flask development server is a deliberate simulation-scale choice, not a deployment story. And the stochastic rules stand in for real telemetry — a production system would evaluate velocity against actual transaction history, not a probability. Naming your own limitations unprompted is one of the strongest signals you can send in a technical interview.

A good next step that fits the project's scale: a small `pytest` suite for `evaluate_rules()` and the severity selection, using `random.seed()` for deterministic tests. That is the natural "what would you do next" answer.

## 8. The 60-second interview narrative

"FraudDetective is a SOC-style triage simulator I built from 2.5 years of real fraud operations at Remitly — the rules are the ones I actually worked: high-risk corridors, gender mismatch as an ATO signal, velocity, mule patterns, PEP/OFAC. The first version worked but had the flaws you'd expect from a first version: the rule cascade and biased data generation made 93% of alerts High, IDs were random four-digit numbers guaranteed to eventually collide, and state changes rode on GET links. I refactored it the way I'd want a real tool reviewed: rules now evaluate independently with the highest-severity hit as the primary and correlated signals surfaced, the distribution measured over 20,000 simulations is about 30% High / 55% Medium / 15% Low, IDs are database-assigned and never reused, every mutating route is POST-only with allowlisted inputs, debug mode is opt-in, and timestamps are UTC. It's still an educational simulation — but it now behaves like the systems it's teaching me to work with."

## Housekeeping for the repo

The schema changed, so delete the old database before first run — it's synthetic data, and `init_db()` recreates it:

```
rm fraudetective.db
pip install -r requirements.txt
python app.py
```

Update the README: the install line becomes `pip install flask` (flask-session is gone), remove Flask-Session from the technologies list, fix the leftover "RemitGuard" name in the description (previous project name), and update the AI Assistance Disclosure to credit both tools — the code comments in this version already do. Optional: swap the lion image on the homepage for something SOC-themed; charming, but a hiring manager will notice. If any part of this project has not yet been submitted to CS50, submit the original version you built for the course and keep this refactor on the portfolio branch — CS50's academic honesty policy applies to coursework, while the portfolio version is yours to improve openly with disclosure.
