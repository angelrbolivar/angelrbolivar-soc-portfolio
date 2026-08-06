# Angel Rodriguez Bolivar — SOC Analyst Portfolio

**Junior SOC Analyst candidate — alert triage, SIEM investigation, and detection documentation.**
Investigations are documented end to end: evidence → verdict → MITRE mapping → recommendations.

---

## Core Evidence

### 1. Azure Sentinel — Honeypot Brute-Force Investigation

**→ Read the full investigation**

End-to-end investigation of live attack traffic against a deliberately exposed honeypot in Microsoft Sentinel.

* Analyzed **728 failed authentication attempts** — log review, source IP and geolocation enrichment, attack timeline reconstruction
* Configured Sentinel analytics rules that generated incidents from live attack traffic
* Documented a **True Positive** verdict with supporting evidence
* Mapped to **MITRE ATT&CK T1110 (Brute Force)**, with hardening recommendations

> Environment and detection approach follow Josh Madakor's guided honeypot lab; I adapted the KQL rather than authoring it from scratch. The investigation, evidence handling, verdict, and recommendations are my own work.

### 2. KQL Detection Rules

**→ detections/kql-brute-force-rules.md**

Brute-force detection logic — failed-logon thresholds and source-IP aggregation — tested against the real attack traffic above rather than synthetic data.

### 3. Alert Triage Dashboard

**→ alert-triage-dashboard/**

A fraud alert triage simulator built from the production queue and decision workflow I worked in daily: review the alert, weigh partial signals, decide, justify the decision.

### 4. TryHackMe — SIEM Triage Labs

**→ labs/tryhackme/**

Guided triage investigations in **Splunk** and **Elastic**, documented with investigation screenshots. Focus: log analysis, alert validation, and True / False Positive determination.

### 5. Blue Team Labs Online — Splunk Investigations `IN PROGRESS`

**→ labs/btlo/** *(write-up pending)*

Hands-on Splunk investigations on Blue Team Labs Online, currently underway. Work in progress: SPL search construction, log correlation across sources, and verdict determination on scenario-based incidents.

> **Status:** investigation active, not yet complete. The full write-up and investigation screenshots — documented in the same evidence → verdict → recommendation format as the Sentinel case above — will be added to this repository once the work is finished. No findings are claimed here until that write-up is published.

---

## Background

**Remitly (via Sutherland) — 2 years of production fraud & risk alert triage.**
High-volume alert queue under SLA: live cases, incomplete and sometimes conflicting evidence, and a decision with real consequences at the end of every one. The decision model maps directly onto SOC triage:

| Fraud & risk triage | SOC alert triage |
| --- | --- |
| High-volume queue, SLA-bound | Same |
| Approve / Suspend / Escalate | Benign / True Positive / Escalate |
| Decisions on incomplete evidence | Same |
| Written case justification | Investigation notes and verdict |

**Certifications & education**

* CompTIA Security+ (SY0-701) — **785/900**
* Google Cybersecurity Professional Certificate
* TryHackMe SOC Level 1
* Harvard CS50x
* Bilingual — English (C2) / Spanish (native)

---

## Skills Demonstrated

* Alert triage and True / False Positive determination
* **KQL** — brute-force detection logic validated against real attack traffic
* **Microsoft Sentinel** — Log Analytics ingestion, analytics rule configuration, incident investigation
* **Splunk** — SPL search and log correlation; guided triage labs completed (TryHackMe), with scenario-based investigations on Blue Team Labs Online **currently in progress**
* **Elastic** — log search and alert validation (guided labs)
* MITRE ATT&CK mapping
* Investigation documentation: evidence → verdict → recommendation
* Decision-making under incomplete information

---

## Repository Structure

```
.
├── detections/
│   └── kql-brute-force-rules.md              # KQL rules validated on live attack traffic
├── labs/
│   ├── azure-sentinel/
│   │   └── investigation-honeypot-bruteforce.md
│   ├── tryhackme/                            # Splunk & Elastic triage labs
│   └── Splunkit/                                 # Blue Team Labs Online — Splunk (write-up in progress)
├── alert-triage-dashboard/                   # Fraud alert triage simulator
└── playbooks/                                # Documentation about procedures in cybersecurity
```

---

## Contact

* **GitHub:** [@angelrbolivar](https://github.com/angelrbolivar)
* **LinkedIn:** [Angel Rodriguez Bolivar](https://linkedin.com/in/angel-rodriguez-bolivar-3a6166361/)

Open to Junior SOC Analyst roles focused on alert triage and investigation.
