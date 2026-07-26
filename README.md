# Angel Rodriguez Bolivar — SOC Analyst Portfolio

**Junior SOC Analyst candidate focused on alert triage and investigation documentation.**

Completed SIEM investigations with evidence, verdicts, MITRE mapping, and recommendations.

---

## Core Evidence

### [Azure Sentinel — Honeypot Brute-Force Investigation](labs/azure-sentinel)

End-to-end investigation of real attack traffic against a deliberately exposed honeypot, in Microsoft Sentinel.

- Performed the **end-to-end investigation of 728 failed authentication attempts** targeting the honeypot — log analysis, attacker IP and geolocation enrichment, attack timeline reconstruction
- **Adapted and tested KQL queries** to detect brute-force patterns (failed-logon thresholds, source-IP aggregation) and configured Sentinel analytics rules that generated incidents from live attack traffic
- Documented a **True Positive** verdict with supporting evidence
- Mapped the activity to **MITRE ATT&CK T1110 (Brute Force)** and delivered hardening recommendations

> Environment and detection approach follow Josh Madakor's guided honeypot lab; I adapted the KQL rather than authoring it from scratch. The investigation, evidence handling, verdict, and recommendations are my own work.

### [TryHackMe — SIEM Alert Triage](labs/tryhackme)

Guided-lab triage investigations across two SIEM platforms, documented with investigation screenshots.

- [**Alert Triage with Splunk**](labs/tryhackme/alert-triage-with-splunk)
- [**Alert Triage with Elastic**](labs/tryhackme/alert-triage-with-elastic)

Focus: log analysis, alert validation, and clear True Positive identification.

---

## Background

- **Remitly — 2 years of production fraud & risk alert triage.** Approve / Suspend / Escalate decisions on live cases under incomplete information — the same judgment model as SOC alert triage.
- **CompTIA Security+ (SY0-701) — 785/900**
- **Google Cybersecurity Professional Certificate**
- **TryHackMe SOC Level 1**
- **Harvard CS50x**
- **Bilingual — English (C2) / Spanish (native)**

---

## Skills Demonstrated

- Alert triage and True / False Positive determination
- Log analysis — KQL (foundational); Splunk & Elastic via guided labs
- Microsoft Sentinel — log ingestion (Log Analytics), analytics rule configuration from adapted KQL, incident investigation
- Investigation documentation: evidence → verdict → recommendation
- Decision-making under incomplete information

---

## Contact

- **GitHub:** [@angelrbolivar](https://github.com/angelrbolivar)
- **LinkedIn:** [Angel Rodriguez Bolivar](https://www.linkedin.com/in/angel-rodriguez-bolivar-3a6166361/)
