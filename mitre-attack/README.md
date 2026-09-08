# MITRE ATT&CK Mapping

This section documents how the custom Wazuh detection rules were mapped to MITRE ATT&CK techniques during the Detection Engineering & Alert Triage project.

The project used MITRE ATT&CK to identify adversary behaviors and translate those behaviors into practical SIEM detection logic.

## Objective

The objective of the MITRE ATT&CK mapping was to:

- Identify relevant attacker techniques
- Map each technique to a detection rule
- Associate detections with the appropriate ATT&CK tactic
- Design detection logic around observable endpoint behavior
- Validate the detections through controlled simulation
- Document detection coverage and limitations

## Detection Coverage

Six custom Wazuh rules were created across five MITRE ATT&CK tactics.

| Rule ID | ATT&CK Technique | Technique Name | Tactic | Wazuh Level | Result |
|---|---|---|---|---:|---|
| 100400 | T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | 8 | Detected |
| 100401 | T1070.001 | Indicator Removal: Clear Windows Event Logs | Defense Evasion | 12 | Detected |
| 100402 | T1082 | System Information Discovery | Discovery | 5 | Detected |
| 100403 | T1033 | System Owner/User Discovery | Discovery | 5 | Detected |
| 100404 | T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access | 15 | Prevented |
| 100405 | T1105 | Ingress Tool Transfer | Command and Control | 10 | Prevented |

Four of the six detection scenarios were successfully validated against live simulated telemetry. Two simulations were prevented by Windows Defender before the underlying behaviors could execute successfully. :contentReference[oaicite:1]{index=1}

---

# ATT&CK Tactics Covered

The detection portfolio covered the following ATT&CK tactics:

- Persistence
- Defense Evasion
- Discovery
- Credential Access
- Command and Control

This provided detection coverage across different stages of adversary activity rather than concentrating on a single attack phase.

---

# Technique 1 — T1053.005

## Scheduled Task/Job: Scheduled Task

**Rule ID:** 100400

**Tactic:** Persistence

**Wazuh Level:** 8

### Detection Logic

The rule detects `schtasks.exe` execution when the command line contains the `/create` parameter.

This behavior can indicate the creation of a scheduled task that may be used to establish persistence.

### Simulation

The technique was simulated using Atomic Red Team.

The test created two scheduled tasks:

- `T1053_005_OnLogon`
- `T1053_005_OnStartup`

The Wazuh rule successfully detected the scheduled-task activity. :contentReference[oaicite:2]{index=2}

### Result

**Detected**

The rule fired twice from the simulation because two scheduled tasks were created.

---

# Technique 2 — T1070.001

## Indicator Removal: Clear Windows Event Logs

**Rule ID:** 100401

**Tactic:** Defense Evasion

**Wazuh Level:** 12

### Detection Logic

The rule detects Windows Security Event ID 1102.

Event ID 1102 is generated when the Windows Security audit log is cleared.

### Simulation

There was no maintained Atomic Red Team test case for T1070.001 in the installed library.

Instead of skipping validation, the underlying behavior was manually reproduced using the Windows command:

`wevtutil cl Security`

The action generated Security Event ID 1102, which was successfully detected by Wazuh. :contentReference[oaicite:3]{index=3}

### Result

**Detected**

The resulting alert also captured the account responsible for clearing the log.

---

# Technique 3 — T1082

## System Information Discovery

**Rule ID:** 100402

**Tactic:** Discovery

**Wazuh Level:** 5

### Detection Logic

The rule detects the creation of the `systeminfo.exe` process.

The command provides information about the Windows system and can be used during reconnaissance.

### Simulation

The technique was simulated using Atomic Red Team.

The detection fired on the first attempt.

The parent command line showed `systeminfo` chained with a registry query, which provided additional context consistent with a scripted reconnaissance step. :contentReference[oaicite:4]{index=4}

### Result

**Detected**

The detection successfully identified the expected system-information discovery activity.

---

# Technique 4 — T1033

## System Owner/User Discovery

**Rule ID:** 100403

**Tactic:** Discovery

**Wazuh Level:** 5

### Detection Logic

The rule detects the creation of the `whoami.exe` process.

The command identifies the current user and can be used by an attacker to understand the account context of a compromised system.

### Simulation

The technique was simulated through both direct `whoami.exe` execution and PowerShell-invoked execution.

The rule fired five times during repeated testing. :contentReference[oaicite:5]{index=5}

### Result

**Detected**

The rule successfully detected the user-discovery activity across different execution contexts.

---

# Technique 5 — T1003.001

## OS Credential Dumping: LSASS Memory

**Rule ID:** 100404

**Tactic:** Credential Access

**Wazuh Level:** 15

### Detection Logic

The rule was designed to detect `rundll32.exe` invoking `comsvcs.dll` with the `MiniDump` argument.

This behavior is associated with attempting to dump LSASS memory and potentially obtain credential material.

The detection logic was defined around:

- `rundll32.exe`
- `comsvcs.dll`
- `MiniDump`

The project report defines this rule as Rule 100404 mapped to T1003.001. :contentReference[oaicite:6]{index=6}

### Simulation

The LSASS dumping behavior was attempted during the simulation phase.

However, Windows Defender blocked the activity before the underlying command could successfully execute.

### Result

**Prevented**

The detection rule was therefore not directly validated through a successful LSASS dump.

The project intentionally did not weaken or disable Windows Defender simply to force the detection to fire. :contentReference[oaicite:7]{index=7}

---

# Technique 6 — T1105

## Ingress Tool Transfer

**Rule ID:** 100405

**Tactic:** Command and Control

**Wazuh Level:** 10

### Detection Logic

The rule detects `certutil.exe` execution with the `-urlcache` parameter.

The behavior can be associated with transferring files into an environment using a native Windows utility.

The project report defines Rule 100405 as a T1105 detection based on `certutil.exe` and the `-urlcache` flag. :contentReference[oaicite:8]{index=8}

### Simulation

The technique was attempted using Atomic Red Team and through direct manual testing.

Windows Defender blocked both attempts before the intended transfer behavior could successfully execute.

### Result

**Prevented**

The successful execution of the technique was not confirmed, so the Wazuh detection rule remains unvalidated against live successful execution.

The prevention result was documented as an endpoint security-control finding rather than a failure of the detection logic. :contentReference[oaicite:9]{index=9}

---

# ATT&CK Mapping Summary

| ATT&CK ID | Technique | Tactic | Rule | Result |
|---|---|---|---:|---|
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | 100400 | Detected |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Defense Evasion | 100401 | Detected |
| T1082 | System Information Discovery | Discovery | 100402 | Detected |
| T1033 | System Owner/User Discovery | Discovery | 100403 | Detected |
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access | 100404 | Prevented |
| T1105 | Ingress Tool Transfer | Command and Control | 100405 | Prevented |

---

# Detection Engineering Approach

The project followed a consistent approach for translating ATT&CK techniques into SIEM detections:

**MITRE ATT&CK Technique**

↓

**Identify Observable Behavior**

↓

**Identify Available Telemetry**

↓

**Create Wazuh Detection Logic**

↓

**Simulate the Technique**

↓

**Validate the Alert**

↓

**Triage the Result**

This approach helped connect the theoretical ATT&CK framework to practical detection engineering.

---

# Detection Validation

Four techniques successfully generated the expected Wazuh alerts:

- T1053.005 — Scheduled Task
- T1070.001 — Clear Windows Event Logs
- T1082 — System Information Discovery
- T1033 — System Owner/User Discovery

Two techniques were prevented by endpoint protection:

- T1003.001 — LSASS Credential Dumping
- T1105 — Ingress Tool Transfer

The two prevented techniques were not treated as failed detections because Windows Defender stopped the underlying behaviors before the detection conditions could occur. :contentReference[oaicite:10]{index=10}

---

# Detection Gaps

## Windows-Only Simulation Coverage

All attack simulation testing in this project was performed against the Windows endpoint.

The Linux endpoint was part of the overall SIEM environment, but adversary simulation was not performed against it during this project.

This represents an area for future improvement.

## Two Rules Not Directly Validated

Rules 100404 and 100405 have defined detection logic and MITRE ATT&CK mappings, but successful live execution was not achieved because Windows Defender prevented the underlying techniques.

This limitation was documented rather than bypassed by disabling security controls. :contentReference[oaicite:11]{index=11}

---

# Key Lessons

The MITRE ATT&CK mapping phase helped me understand how adversary behavior can be translated into practical detection requirements.

I learned how to:

- Map attacker behaviors to ATT&CK techniques
- Identify the tactic associated with each technique
- Determine what endpoint behavior can be monitored
- Translate observable behavior into Wazuh detection logic
- Validate detections through controlled simulation
- Understand the difference between detection and prevention
- Document detection limitations honestly
- Use ATT&CK as a framework for building structured detection coverage

---

# Conclusion

The MITRE ATT&CK framework provided the foundation for the detection engineering work in this project.

Rather than creating arbitrary SIEM rules, each custom Wazuh rule was associated with a specific adversary technique and designed around observable endpoint behavior.

The project successfully validated four of the six detection scenarios while also demonstrating how endpoint prevention can stop two simulated behaviors before successful execution.

This provided practical experience connecting **MITRE ATT&CK, endpoint telemetry, detection engineering, SIEM alerting, and SOC triage**.

---

## Related Project Sections

- [Detection Rules](../detection-rules/README.md)
- [Attack Simulation](../attack-simulation/README.md)
- [Alert Triage](../alert-triage/README.md)
