# Incident Investigation — Honeypot Brute-Force Attack

**True Positive** · RDP brute-force against an intentionally exposed honeypot

| | |
|---|---|
| **Incident** | Honeypot - High Volume Failed Logons from Single IP |
| **Date** | July 24, 2026 |
| **Analyst** | Angel Rodriguez Bolivar |
| **Host** | `CORP-NET-TINY-E1` (intentional honeypot) |
| **Severity** | Medium |
| **Status** | Closed — True Positive |

---

## 1. Alert Summary

The Microsoft Sentinel analytics rule **Honeypot - High Volume Failed Logons from Single IP** (Medium severity) fired on `CORP-NET-TINY-E1`, a deliberately internet-exposed honeypot VM with **no legitimate users**. The rule triggers on ≥ 15 failed logons (Event ID `4625`) from a single source IP within a 1-hour window.

The top offender, **`197.255.224.193`**, generated **728 failed RDP logon attempts across 8 distinct accounts** in approximately one hour (~12:39 PM – 1:39 PM). Multiple additional external IPs also exceeded the ≥ 15 threshold during the same period, consistent with broad opportunistic scanning of the exposed host.

## 2. Initial Indicators

- **Source IP `197.255.224.193`** — 728 failed logon attempts, 8 distinct target usernames
- **Multiple secondary IPs** above the ≥ 15 failed-attempt threshold in the same window
- **Time window:** ~12:39 PM – 1:39 PM, July 24, 2026
- **Event ID:** `4625` (failed logon), RDP authentication attempts
- **Baseline context:** the host is a honeypot with zero legitimate users — *any* authentication activity is suspicious by definition

## 3. Evidence / Logs Checked

**Log source:** `SecurityEvent` table (Windows Security log → Log Analytics Workspace → Sentinel)

The investigation was conducted directly from the Sentinel incident and the alert's underlying query results:

- **Alert results reviewed:** the rule's output table showed **728 failed logon attempts (`4625`) from `197.255.224.193` across 8 distinct usernames** on `CORP-NET-TINY-E1`, with first/last attempt timestamps spanning the ~12:39 PM – 1:39 PM window.
- **Secondary offenders:** the same results showed **multiple additional external IPs** exceeding the ≥ 15 failed-attempt threshold in the same period — consistent with broad, distributed opportunistic scanning rather than a single misconfigured client.
- **Baseline check:** `CORP-NET-TINY-E1` is an isolated honeypot with no legitimate users or scheduled authentication, so every observed logon attempt is attacker traffic by definition — no benign explanation exists.
- **Compromise check:** based on the alert context and review of the host's authentication activity during the investigation, **no successful logons were observed** from any attacking IP.

**Evidence summary:**

- Attack volume and account rotation confirmed directly from the alert's query results (raw `4625` telemetry)
- No successful logons observed → no evidence of compromise
- Multi-source activity confirms real, distributed internet attack traffic

## 4. Timeline

*All times approximate, July 24, 2026.*

| Time | Event |
|------|-------|
| ~12:39 PM | First failed logon from `197.255.224.193` observed on `CORP-NET-TINY-E1` |
| 12:39 PM – 1:39 PM | Sustained brute-force activity: 728 failures (~12 attempts/min average), rotating through 8 usernames; secondary IPs active in parallel |
| During window | Sentinel rule threshold (≥ 15 failures / 1h) crossed on scheduled evaluation → incident created |
| ~1:39 PM | Last observed failed attempt from the primary IP |
| Post-alert | Alert results and host authentication activity reviewed; no successful logons observed; incident classified and closed as True Positive |

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed Behavior |
|--------|-----------|----|-------------------|
| Initial Access | External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) | Authentication attempts against internet-exposed RDP |
| Credential Access | Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | High-volume failed logons from multiple external IPs |
| Credential Access | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | 728 repeated failures from a single IP (primary technique for this rule) |

> **Note:** The rotation across 8 distinct usernames is also consistent with password spraying ([T1110.003](https://attack.mitre.org/techniques/T1110/003/)) or credential stuffing ([T1110.004](https://attack.mitre.org/techniques/T1110/004/)). Failed-logon telemetry alone cannot distinguish which password strategy was used, so T1110.001 is retained as the primary mapping per the triggering rule.

## 6. Verdict + Actions

**Verdict: True Positive.** The activity is genuine malicious brute-forcing from external sources, and the detection rule fired exactly as designed.

Because the target is an **intentional honeypot** — isolated, with no legitimate users and no production adjacency — this activity is *expected by design* and required no containment.

**Actions taken:**

- Reviewed the host's authentication activity — no successful logons observed from any attacking IP
- Verified honeypot isolation (no lateral movement paths to production resources)
- Recorded IOCs: `197.255.224.193` plus all secondary over-threshold IPs
- Documented findings and closed the incident as **True Positive**

**Production-equivalent response** (what these actions would be on a real asset):

- Block source IPs at the NSG / perimeter firewall
- Remove direct RDP internet exposure (Azure Bastion, VPN, or Just-in-Time access)
- Enforce account lockout policy and MFA on all remote access
- Escalate per brute-force playbook and review targeted accounts for prior suspicious activity

## 7. Lessons / Detection Improvement Ideas

- **Formalize the verification step:** build a saved triage checklist with explicit KQL verification queries — most importantly a per-IP success check (`4624` from any attacking source) — so every future investigation includes a documented, repeatable compromise check rather than relying on alert context alone.
- **Correlation rule for compromise:** add a High-severity rule joining `4625` bursts with a subsequent `4624` from the same IP — the highest-value gap, since it detects a *successful* brute force rather than just attempts.
- **GeoIP enrichment:** enrich alerts and build a workbook mapping attack origins; traffic arrived from multiple countries and visualization aids reporting and triage.
- **IOC reuse:** feed honeypot attacker IPs into a Sentinel watchlist to enrich detections on production-facing resources — turning the honeypot into a live threat-intel source.
- **SOAR automation:** a Logic App playbook to auto-block repeat offenders at the NSG would demonstrate response automation with near-zero risk on a honeypot.
- **Tiered severity:** 728 attempts vastly exceeds the 15-attempt threshold; a second, higher threshold (or dynamic severity) would help analysts prioritize the loudest offenders.
- **Richer telemetry:** capture `LogonType` and process context in rule output, and consider Sysmon for deeper visibility if attacker tooling ever lands on the host.
