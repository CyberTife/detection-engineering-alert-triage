# Detection Engineering & Alert Triage

## SOC Analyst Training — Project 2

> From MITRE ATT&CK technique selection to detection logic, adversary simulation, alert generation, and SOC triage.

---

## 📌 Project Overview

This project demonstrates practical **detection engineering and security alert triage** using **Wazuh 4.14.6**, **Windows endpoint telemetry**, **Sysmon**, and **Atomic Red Team**.

The project builds on an existing SIEM lab and moves beyond passive log collection into active detection engineering.

The primary objective was to map attacker behaviors to the **MITRE ATT&CK framework**, translate those behaviors into working Wazuh detection rules, safely simulate the techniques, validate the resulting telemetry, and apply a consistent SOC alert-triage workflow.

Six custom Wazuh detection rules were developed across multiple MITRE ATT&CK tactics:

- Persistence
- Defense Evasion
- Discovery
- Credential Access
- Command and Control

---

## 🎯 Project Objectives

- Develop custom Wazuh detection rules.
- Map detections to MITRE ATT&CK techniques.
- Generate realistic endpoint telemetry.
- Simulate adversary behavior in an isolated lab.
- Validate detection rules using Wazuh alerts.
- Investigate and triage generated alerts.
- Identify false-positive scenarios.
- Document prevented attack activity.
- Apply SOC escalation and closure decisions.
- Evaluate detection coverage and identify improvement areas.

---

## 🧪 Lab Environment

| Component | Technology |
|---|---|
| SIEM | Wazuh 4.14.6 |
| Windows Endpoint | Windows |
| Endpoint Telemetry | Sysmon |
| Attack Simulation | Atomic Red Team |
| Detection Framework | MITRE ATT&CK |
| Linux Endpoint | Ubuntu/Linux |
| Firewall Simulation | Lab-based simulated firewall |

The environment was operated as an isolated security-training laboratory.

---

## 🔍 Detection Portfolio

Six custom Wazuh detection rules were developed and tested.

| Rule ID | MITRE ATT&CK | Technique | Tactic | Result |
|---|---|---|---|---|
| 100400 | T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | ✅ Validated |
| 100401 | T1070.001 | Indicator Removal: Clear Windows Event Logs | Defense Evasion | ✅ Validated |
| 100402 | T1082 | System Information Discovery | Discovery | ✅ Validated |
| 100403 | T1033 | System Owner/User Discovery | Discovery | ✅ Validated |
| 100404 | T1003.001 | OS Credential Dumping: LSASS | Credential Access | ⚠️ Blocked by Defender |
| 100405 | T1105 | Ingress Tool Transfer | Command and Control | ⚠️ Blocked by Defender |

### Detection Results

- **6** custom detection rules developed
- **6** detection scenarios tested
- **4** detections successfully validated
- **2** attack scenarios prevented by Windows Defender

The two prevented scenarios were documented rather than weakening endpoint security controls to force execution.

---

## ⚙️ Detection Engineering Workflow

The detection engineering process followed this workflow:

**MITRE ATT&CK Technique Selection**

↓

**Detection Logic Development**

↓

**Wazuh Rule Configuration**

↓

**Endpoint Telemetry Generation**

↓

**Attack Simulation**

↓

**Alert Validation**

↓

**Alert Triage**

↓

**Findings and Documentation**

This approach demonstrates the connection between threat behavior, telemetry, detection logic, and SOC response.

---

## 🧩 Detection Rules

Detailed documentation for each custom Wazuh rule is available in the detection-rules directory.

### Individual Rules

- [Rule 100400 — Scheduled Task Creation](detection-rules/rule-100400.md)
- [Rule 100401 — Clear Windows Event Logs](detection-rules/rule-100401.md)
- [Rule 100402 — System Information Discovery](detection-rules/rule-100402.md)
- [Rule 100403 — System Owner/User Discovery](detection-rules/rule-100403.md)
- [Rule 100404 — LSASS Credential Dumping](detection-rules/rule-100404.md)
- [Rule 100405 — Ingress Tool Transfer](detection-rules/rule-100405.md)

[View Detection Rules Documentation](detection-rules/README.md)

---

## 🧨 Attack Simulation

Attack simulations were performed against the Windows endpoint using **Atomic Red Team** and manual reproduction where required.

Four techniques successfully generated Wazuh detections.

Two techniques were prevented by Windows Defender:

- LSASS credential dumping
- Certutil-based file transfer

The prevention events were treated as valuable security findings rather than failures.

[View Attack Simulation Documentation](attack-simulation/README.md)

---

## 🚨 Alert Triage

Generated alerts were investigated using a structured SOC triage workflow:

**Validate → Identify → Investigate → Classify → Prioritize → Escalate or Close → Document**

The project included:

- Real alerts generated during simulations
- Defender-prevented activity
- Constructed false-positive scenarios
- Alert classification
- Escalation decisions
- Containment decisions
- Documentation of analyst findings

[View Alert Triage Documentation](alert-triage/README.md)

---

## 🛡️ MITRE ATT&CK Coverage

The detection portfolio was mapped to six MITRE ATT&CK techniques:

- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1070.001** — Indicator Removal: Clear Windows Event Logs
- **T1082** — System Information Discovery
- **T1033** — System Owner/User Discovery
- **T1003.001** — OS Credential Dumping: LSASS
- **T1105** — Ingress Tool Transfer

The project covered techniques across:

- Persistence
- Defense Evasion
- Discovery
- Credential Access
- Command and Control

[View MITRE ATT&CK Mapping](mitre-attack/README.md)

---

## 📊 Project Findings

The project produced several important findings:

- Four of six detection scenarios successfully generated Wazuh alerts.
- Windows Defender prevented two simulated attack behaviors.
- The detection rules successfully identified multiple endpoint discovery and persistence behaviors.
- Alert context was important when distinguishing malicious activity from legitimate administrative activity.
- Two false-positive scenarios demonstrated the importance of contextual investigation.
- Detection rules were not weakened to force blocked simulations to succeed.
- Lab infrastructure issues were investigated separately from detection-rule issues.
- The project highlighted the need for broader cross-platform detection validation.

[View Project Findings](findings/README.md)

---

## 🧠 Key Skills Demonstrated

### Detection Engineering

- Custom Wazuh rule development
- Detection logic creation
- Rule validation
- Endpoint telemetry analysis
- Detection coverage assessment

### SOC Analysis

- Alert validation
- Alert investigation
- Alert classification
- Severity assessment
- False-positive analysis
- Escalation decisions
- Containment decisions
- Security event documentation

### Threat Detection

- MITRE ATT&CK mapping
- Adversary behavior simulation
- Windows endpoint monitoring
- Sysmon telemetry analysis
- Atomic Red Team testing
- Security-control validation

### Security Operations

- SIEM monitoring
- Endpoint detection
- Security event analysis
- Detection gaps identification
- Detection tuning considerations
- Incident-response decision making

---

## 📚 Lessons Learned

This project reinforced several important SOC principles:

1. Detection engineering must be validated against real telemetry.
2. A security alert does not automatically mean malicious activity.
3. Alert context is critical when determining whether activity is malicious or legitimate.
4. Preventive security controls can stop an attack before the expected detection telemetry is generated.
5. A blocked attack can still provide valuable security findings.
6. Detection rules should not be weakened simply to increase test success.
7. MITRE ATT&CK provides a useful framework for organizing detection coverage.
8. Effective SOC analysis requires both technical investigation and contextual reasoning.
9. Detection engineering is an iterative process that requires continuous testing and improvement.

---

## 🚀 Future Improvements

Future iterations of this project could include:

- Additional Windows detection rules
- More Linux-focused detections
- Cross-platform detection validation
- Additional Atomic Red Team simulations
- More complex attack chains
- Alert correlation across multiple events
- Continuous detection tuning
- Additional endpoint telemetry sources
- A living SOC triage playbook
- More advanced investigation and escalation scenarios

---

## 📁 Repository Structure

```text
detection-engineering-alert-triage/
│
├── attack-simulation/
│   └── README.md
│
├── detection-rules/
│   ├── README.md
│   ├── rule-100400.md
│   ├── rule-100401.md
│   ├── rule-100402.md
│   ├── rule-100403.md
│   ├── rule-100404.md
│   └── rule-100405.md
│
├── findings/
│   └── README.md
│
├── mitre-attack/
│   └── README.md
│
└── README.md
