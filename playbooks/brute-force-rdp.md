# Brute Force – Failed RDP / Authentication Logons

**Playbook ID:** PB-BF-001 · **Version:** 1.0 · **Updated:** 2026-07-28 · **Owner:** SOC
**Default severity:** Medium — raise per §8 on any success.
**MITRE ATT&CK:** T1110 (Brute Force) · T1110.001 (Password Guessing) · T1133 (External Remote Services)

---

## 1. Purpose & Scope

Standard triage and response for failed-authentication brute force (Windows EventID 4625) against RDP-exposed hosts monitored in Microsoft Sentinel. Applies to **production assets and designated honeypots** (e.g., `CORP-NET-TINY-E1`).

**Out of scope:** confirmed compromise (hand off to the Intrusion/IR playbook after §8), password spraying against Entra ID / cloud identities (separate playbook).

## 2. Trigger Conditions

Any of these three Sentinel analytics rules. Thresholds below are the deployed baseline — if the rule config changes, update this table.

| Rule | Logic | Threshold | Window |
|---|---|---|---|
| **BF-01 — Single-IP high volume** | ≥ N failed logons (4625) from one source IP against one host | ≥ 100 failures | 1 h |
| **BF-02 — Multi-username, same IP** | One source IP fails against ≥ N distinct accounts | ≥ 5 accounts | 1 h |
| **BF-03 — Burst activity** | Rapid failure spike from one source IP | ≥ 25 failures | 5 min |

**Reference case:** `197.255.224.193` → 728 × 4625 across 8 accounts on `CORP-NET-TINY-E1` in ~1 h, plus several secondary IPs over threshold. Trips all three rules. No 4624 observed.

## 3. Required Data Sources

- **SecurityEvent** (Windows Security Events via AMA) — EventIDs **4625, 4624, 4740, 4672**
- **Sentinel Watchlists** — `HoneypotAssets`, `AuthorizedScanners`, `VIPAccounts`
- **Threat intel enrichment** — internal TI feed; external: AbuseIPDB, GreyNoise (known-scanner check)
- **Asset inventory / CMDB** — asset classification, owner, exposure
- **Azure NSG flow logs** (optional) — confirm inbound 3389 reachability, other ports probed

## 4. Investigation Steps

> **5-minute path:** run Step 1 and Step 3. Zero 4624 rows → contain per §6, document per §7.
> Replace IPs/host/accounts in each query with the entities from your alert.

**1. Scope the failure activity — who, which accounts, how fast.**

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| where Computer =~ "CORP-NET-TINY-E1"        // alert host
| summarize Failures = count(),
            Accounts = dcount(TargetUserName),
            AccountList = make_set(TargetUserName, 25),
            First = min(TimeGenerated), Last = max(TimeGenerated)
    by IpAddress, LogonType
| order by Failures desc
```

> **Why LogonType matters:** with NLA enabled, failed RDP logs as **LogonType 3** (network), not 10. Never filter to LogonType 10 only — you'll miss most RDP brute force.

**2. Read the failure reasons — SubStatus tells you what the attacker knows.**

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| where IpAddress in ("197.255.224.193")      // all flagged IPs
| summarize Count = count() by TargetUserName, SubStatus
| order by Count desc
```

| SubStatus | Meaning | Signal |
|---|---|---|
| `0xC0000064` | Username does not exist | Guessing usernames — commodity noise |
| `0xC000006A` | Wrong password, **valid user** | Attacker has real usernames — higher risk |
| `0xC0000234` | Account locked out | Impact — check Step 4 |
| `0xC0000072` | Account disabled | Stale creds, low risk |

**3. SUCCESS CHECK — mandatory before any verdict.** Run both queries.

```kql
// 3a. Any success FROM the suspect IP(s), on any host
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where IpAddress in ("197.255.224.193")      // all flagged IPs
| project TimeGenerated, Computer, TargetUserName, LogonType, IpAddress, LogonProcessName
```

```kql
// 3b. Any success FOR the targeted accounts from ANY IP
//     (catches success from a different attacker node)
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where TargetUserName in~ ("admin", "administrator", "user1")   // AccountList from Step 1
| where LogonType in (3, 10)
| where IpAddress != "-" and not(TargetUserName endswith "$")
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonType
```

**Zero rows on both = no compromise via this activity. Any row → stop and escalate per §8.**

**4. Check lockout collateral.**

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4740
| project TimeGenerated, TargetUserName, Computer
```

**5. Classify the asset.** Check `HoneypotAssets` watchlist / CMDB. `CORP-NET-TINY-E1` = intentional Azure honeypot → follow the honeypot path in §6.

**6. Check blast radius — is this IP hitting anything else?**

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| where IpAddress in ("197.255.224.193")
| summarize Failures = count(), FirstSeen = min(TimeGenerated) by Computer
```

Any **production** host in the results → work it as a production incident, not honeypot-only.

**7. Enrich source IPs and judge the account list.** TI verdict, geo/ASN, GreyNoise scanner status. Generic accounts (`admin`, `test`, `scanner`) = commodity spraying. Real employee usernames = possible targeted attack or leaked user list → note in ticket, weigh §8.

## 5. Decision Points / Verdict Criteria

| Verdict | Criteria | Path |
|---|---|---|
| **True Positive — blocked attack** | Threshold exceeded, external untrusted IP(s), Step 3 = zero successes | §6 containment → close TP, no impact |
| **True Positive — compromise** | Any 4624 correlated to the activity (same IP, or targeted account success in window) | Stop. §8 escalation → IR playbook |
| **False Positive** | Internal source; one account failing mechanically (service/app with expired creds, uniform interval); source in `AuthorizedScanners` | Ticket to asset owner; tune rule if recurring |
| **Benign** | Low count, single account, human typo pattern, followed by legit 4624 from same user context | Close benign |

**Honeypot note:** brute force against a honeypot is *expected*, but it is still a **True Positive** — real attacker activity. The difference is the response path (§6), not the verdict.

## 6. Containment & Response Actions

### If asset is a honeypot (`CORP-NET-TINY-E1`)

1. **Do NOT block source IPs at the honeypot** — blocking kills the intel collection it exists for.
2. Verify isolation is intact: no NSG route from honeypot subnet to production, no shared credentials with any production system.
3. Export attacker IPs + targeted usernames to the TI watchlist. Optionally push the IPs to **production** perimeter blocks — that doesn't affect the honeypot.
4. Reconfirm Step 3 = zero successes. If a honeypot ever shows a 4624, treat as compromised: review what executed, then rebuild it — honeypots are disposable.
5. Tag and close per honeypot handling procedure.

### If asset is production

1. **Block source IP(s)** at NSG / perimeter firewall. Sanity-check for CGNAT/shared-IP collateral before blocking ranges tied to business-relevant regions.
2. **If any success:** isolate the host (NSG deny-all / Defender for Endpoint isolate), reset affected accounts, revoke sessions, escalate to IR immediately.
3. Locked accounts (4740): unlock via helpdesk **only after** the source is blocked.
4. **Kill the exposure — this is the real fix:** public 3389 should not exist. Move access behind VPN / Azure Bastion / Defender for Cloud JIT; enforce NLA, account lockout policy, MFA where applicable.
5. Re-run Step 3 queries 24 h later for the same IPs and accounts.

## 7. Documentation Requirements

Every incident ticket must contain:

- Alert rule name(s) + alert IDs; which threshold(s) tripped
- Source IPs with failure counts; targeted account list; time window
- **Success-check output** (Step 3) pasted into the ticket — zero rows or hits; this is the evidence behind the verdict
- Asset classification (honeypot / production) and how it was confirmed
- Verdict + one-line rationale; MITRE mapping (T1110.001, T1133)
- Actions taken (blocks, TI additions, resets) with timestamps
- Detection gaps noticed → add to §9 backlog

## 8. Escalation Criteria

Escalate to Tier 2 / IR **immediately** if any of:

- Any 4624 correlated with the activity (IP match or targeted-account success in window) — treat as active intrusion
- Privileged / VIP / service accounts targeted with valid-user failures (`0xC000006A`)
- Same source IP(s) active against **production** hosts (Step 6)
- Lockout storm (4740) with business impact
- Honeypot shows **post-auth** activity — process creation, persistence, anything beyond failed auth
- You cannot complete Step 3 (missing logs = cannot rule out compromise)

## 9. Detection Improvement Notes

Backlog from the `CORP-NET-TINY-E1` investigation:

1. **Add the highest-value companion rule:** 4625 burst followed by 4624 from the same IP within 1 h. Current rules only see failures — success correlation is manual (Step 3).
2. **Auto-enrich at alert creation** (Logic App): TI verdict + GreyNoise tag on `IpAddress`, so Tier-1 skips the manual lookup.
3. **Route honeypot alerts to an intel queue** at Informational severity via the `HoneypotAssets` watchlist. 728-event storms from a honeypot are expected; keeping them in the Tier-1 queue burns triage time and breeds alert fatigue.
4. **Add distributed / low-and-slow spray detection** — many IPs, few attempts each per account. None of the three current rules catch it.
5. **Watchlist the observed usernames**; alert if any are later attempted against production hosts (attacker reusing a target list).
6. **Revalidate thresholds against baseline:** 700+/h from one IP is commodity noise on exposed 3389. Thresholds must stay well below observed noise ceilings to catch quieter, more deliberate activity.
