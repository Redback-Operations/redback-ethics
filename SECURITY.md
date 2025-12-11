# Security Policy

## Reporting a Vulnerability

# Security Policy – Sensitive Data Exposure (Redback Project)

This document outlines the mandatory incident response process for suspected or confirmed exposures of sensitive data (e.g., PII, PHI, API keys, passwords, real medical records) in the Redback project, including accidental commits to GitHub, misconfigured permissions, or leaked credentials.

## Why This Policy Exists
- Demonstrates preparedness and accountability to stakeholders and Deakin University
- Minimises legal, reputational, and operational risk
- Ensures compliance with:
  - Australian Privacy Principles (APP 11)
  - Privacy Act 1988 (Cth)
  - Health Records Act 2001 (Vic)
  - Surveillance Devices Act 1999 (Vic)
  - Deakin University Human Research Ethics policies

## Risk-Based Escalation Levels

| Risk Level   | Examples                                              | Escalation Required?                          |
| ------------ | ----------------------------------------------------- | --------------------------------------------- |
| **Low**      | Public documents, press releases, policy docs         | No – log only                                 |
| **Medium**   | De-identified logs, dummy/test datasets               | Yes – log + internal review                   |
| **High**     | Real PII/PHI, passwords, API keys, medical reports    | **Yes** – immediate escalation + containment |

## Incident Response Workflow

| Step | Action                                          | Responsible Party       | Tools / Notes                                      |
| ---- | ------------------------------------------------| ----------------------- | -------------------------------------------------- |
| 1    | **Identify** the exposure                       | Any team member         | GitGuardian, TruffleHog, Gitleaks, scanner alerts, manual discovery, external reports |
| 2    | **Notify Lead** immediately                     | Discoverer              | Slack #redback-security, phone, or GitHub issue tag |
| 3    | **Contain** the exposure                        | Dev / GitHub admin      | Remove file, revoke tokens/keys<br>Use `BFG Repo-Cleaner`, `git filter-repo`, or GitHub's "Remove sensitive data" feature |
| 4    | **Log** the incident                            | Project Lead            | Redback Incident Register (Google Sheets or GitHub Issues template) |
| 5    | **Escalate** if High risk                       | Project Lead            | Notify Redback Board, Unit Chair, Deakin Ethics Officer |
| 6    | **Notify affected individuals / OAIC** (if required) | Ethics Subteam       | Follow APP 11 & OAIC Notifiable Data Breach guidelines |
| 7    | **Remediate & Review**                          | All team members        | Update scanner rules, root-cause analysis, staff training, enforce pre-commit hooks |
| 8    | **Document Lessons Learned**                    | Project Lead + Ethics   | Final report uploaded to Google Drive or GitHub Wiki |
| 9    | **Re-scan** repository                          | Dev team                | Full scan with GitGuardian / TruffleHog / Gitleaks |

## Reporting a Sensitive Data Exposure

If you discover exposed sensitive data (inside or outside the team):

1. **Do NOT** create a public GitHub issue
2. Immediately message the Project Lead and Security Analyst
3. Include:
   - Location (file/path, commit SHA, URL)
   - Type of data exposed
   - How you discovered it

You will receive an acknowledgment within **1 hour** during business hours or **4 hours** outside business hours.

## Template: Incident Report Log (for internal register)
**Date:** YYYY-MM-DD  
**Discovered by:** Name  
**Location:** /path/to/file.ext (commit SHA)  
**Risk Level:** Low / Medium / High  
**Data Type:** e.g., Real PII + PHI, API keys  
**Immediate Actions Taken:**  
**Escalated to:** Redback Board / Ethics Officer / etc.  
**Remediation Steps:**  
**Lessons Learned / Prevention Updates:**  
**Re-scan Completed:** Yes / No (date)

