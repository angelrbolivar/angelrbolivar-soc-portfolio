# KQL Detection Rules — Brute Force / Failed Authentication

Microsoft Sentinel analytics rules for detecting brute-force and credential-stuffing activity against RDP-exposed Windows hosts.

> **Validated against live attack traffic.** These queries were adapted from public Sentinel/KQL detection patterns and tuned in a personal Azure lab using an internet-exposed honeypot VM. They were not written against synthetic data — thresholds were set after observing real inbound attack traffic, including a single source IP that generated **728 failed logons (EventID 4625) across 8 distinct accounts in roughly one hour**. All three rules fired on that traffic and produced Sentinel incidents.

**Data source:** `SecurityEvent` (Windows Security Events via Azure Monitor Agent) → Log Analytics workspace
**Key event:** EventID **4625** — an account failed to log on
**MITRE ATT&CK:** [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force · [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing · [T1133](https://attack.mitre.org/techniques/T1133/) External Remote Services

| # | Rule | Detects | Threshold | Window |
|---|---|---|---|---|
| 1 | High Volume Failed Logons from Single IP | Sustained password guessing | ≥ 15 failures | 1 h |
| 2 | Credential Stuffing — Multiple Usernames from Same IP | Username spraying / stuffing | ≥ 5 accounts **and** ≥ 10 failures | 1 h |
| 3 | High Volume Failed Logons Burst | Automated tooling spikes | ≥ 50 failures | 5 min bins over 30 min |

**Note on `LogonType`:** with Network Level Authentication enabled, failed RDP authentication is logged as **LogonType 3 (Network)**, not 10 (RemoteInteractive). These rules intentionally do not filter on `LogonType` — doing so on type 10 alone would miss most RDP brute-force traffic.

---

## Rule 1 — High Volume Failed Logons from Single IP

**Purpose:** Detect a single source IP generating a sustained volume of failed logons against a host — the classic password-guessing pattern, whether aimed at one account or several.

**MITRE:** T1110 (Brute Force), T1110.001 (Password Guessing), T1133 (External Remote Services)

**Threshold rationale:** 15 failures per hour per source IP sits well above normal user error (forgotten passwords, stale cached credentials) but low enough to catch slow, deliberate guessing. Observed attack traffic ran into the hundreds of failures per hour from one IP, so this threshold has wide margin — deliberately, since the more evasive attacker is the quiet one.

```kusto
SecurityEvent
| where EventID == 4625                              // 4625 = failed logon (4624 = success)
| where TimeGenerated > ago(1h)
| summarize
    FailedAttempts = count(),
    DistinctAccounts = dcount(TargetUserName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    Accounts = make_set(TargetUserName, 20)          // sample of targeted accounts, capped for readability
    by IpAddress, Computer                           // aggregate per source IP + targeted host
| where FailedAttempts >= 15                         // filter AFTER summarize — the threshold applies to the count
| project
    TimeGenerated = LastAttempt,                     // Sentinel needs a TimeGenerated column on the result
    IpAddress,
    Computer,
    FailedAttempts,
    DistinctAccounts,
    Accounts,
    FirstAttempt,
    LastAttempt
```

**Why `FirstAttempt` / `LastAttempt` are projected:** together they give the analyst the attack duration at a glance — 400 failures over 55 minutes is a different behavior profile than 400 over 40 seconds, and it seeds the incident timeline without a second query.

---

## Rule 2 — Credential Stuffing (Multiple Usernames from Same IP)

**Purpose:** Detect one source IP attempting authentication against **many different accounts** — username enumeration, password spraying, or credential stuffing from a leaked list. Behaviorally distinct from Rule 1: the attacker is iterating identities, not passwords.

**MITRE:** T1110 (Brute Force), T1110.001 (Password Guessing), T1133 (External Remote Services)

**Threshold rationale:** 5 distinct accounts from one IP in an hour has no legitimate explanation for a normal endpoint — real users don't rotate identities. The second condition (≥ 10 failures) suppresses the low-noise case where a shared kiosk or jump host produces a few scattered failures across accounts. The reference incident hit 8 accounts from one IP, clearing this comfortably.

```kusto
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize
    FailedAttempts = count(),
    DistinctAccounts = dcount(TargetUserName),       // the pivot for this rule: identity spread, not raw volume
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    Accounts = make_set(TargetUserName, 30)          // larger cap than Rule 1 — the account list IS the evidence here
    by IpAddress, Computer
| where DistinctAccounts >= 5 and FailedAttempts >= 10   // both conditions: identity spread AND enough volume to rule out noise
| project
    TimeGenerated = LastAttempt,
    IpAddress,
    Computer,
    FailedAttempts,
    DistinctAccounts,
    Accounts,
    FirstAttempt,
    LastAttempt
```

**Triage value of the `Accounts` set:** generic names (`admin`, `administrator`, `test`, `scanner`) indicate commodity internet scanning. Real employee usernames indicate the attacker has a valid list — a materially higher-severity finding worth escalating.

---

## Rule 3 — High Volume Failed Logons Burst

**Purpose:** Detect a sharp spike in failed logons against a host within a short window — the signature of automated tooling. This rule aggregates **per host** rather than per source IP, so it still fires when an attacker distributes attempts across many IPs to stay under the per-IP thresholds of Rules 1 and 2.

**MITRE:** T1110 (Brute Force), T1110.001 (Password Guessing)

**Threshold rationale:** 50 failures in a 5-minute bin is a rate no human or misconfigured service produces — that's roughly one failure every 6 seconds, sustained. Tight enough to be a high-confidence indicator of automation, so this rule earns a higher severity than the two above.

```kusto
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(30m)                     // short lookback — this rule is about rate, not total
| summarize
    FailedAttempts = count()
    by bin(TimeGenerated, 5m), Computer              // bin() buckets events into fixed 5m windows = failures per unit time
| where FailedAttempts >= 50                         // ~1 failure every 6 seconds sustained — machine speed, not human
| project
    TimeGenerated,
    Computer,
    FailedAttempts
```

**Design trade-off:** aggregating by host only means the alert carries no source IP — the analyst must pivot back to the raw events to identify the attacker. That's intentional: the rule's job is to catch distributed activity that per-IP rules miss, and adding `IpAddress` to the `summarize` would reintroduce the same blind spot.

---

## Operational Notes

- **Suppression:** honeypot and other intentionally exposed assets generate constant true-positive volume. Route them to a lower-severity intel queue via a watchlist rather than the Tier-1 queue — otherwise these rules become alert fatigue.
- **Success correlation:** none of these three rules confirm compromise. Every alert requires a manual 4624 check against the source IP **and** the targeted accounts before a verdict is reached. See the [brute-force triage playbook](../playbooks/brute-force-rdp.md).
- **Detection gaps** (backlog): distributed low-and-slow spraying (many IPs, few attempts each per account) is not reliably covered; a dedicated 4625 → 4624 success-correlation rule is the highest-value addition to this rule set.
- **Tuning:** thresholds are lab-calibrated. Re-baseline against your own environment before production deployment — an exposed host and an internal segment have entirely different noise floors.
