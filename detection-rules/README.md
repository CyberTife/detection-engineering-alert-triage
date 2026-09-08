# Detection Rules

## Custom Wazuh Detection Engineering

This directory contains the six custom Wazuh detection rules developed for the Detection Engineering & Alert Triage project.

The rules were designed to detect specific attacker behaviors and were mapped to MITRE ATT&CK techniques.

The detection portfolio covers five MITRE ATT&CK tactics:

- Persistence
- Defense Evasion
- Discovery
- Credential Access
- Command and Control

---

## Detection Rule Portfolio

| Rule ID | MITRE ATT&CK Technique | Tactic | Wazuh Level | Result |
|---|---|---|---:|---|
| **100400** | T1053.005 — Scheduled Task | Persistence | 8 | Successfully Fired |
| **100401** | T1070.001 — Clear Windows Event Logs | Defense Evasion | 12 | Successfully Fired |
| **100402** | T1082 — System Information Discovery | Discovery | 5 | Successfully Fired |
| **100403** | T1033 — System Owner/User Discovery | Discovery | 5 | Successfully Fired |
| **100404** | T1003.001 — OS Credential Dumping: LSASS | Credential Access | 15 | Blocked by Defender |
| **100405** | T1105 — Ingress Tool Transfer | Command and Control | 10 | Blocked by Defender |

---

# Detection Engineering Approach

The detection rules followed this general process:

```text
MITRE ATT&CK Technique
        ↓
Identify Attacker Behavior
        ↓
Identify Observable Telemetry
        ↓
Create Wazuh Detection Logic
        ↓
Validate Wazuh Configuration
        ↓
Simulate the Behavior
        ↓
Review Endpoint Telemetry
        ↓
Validate the Alert
        ↓
Document the Result
```

The rules were created in the Wazuh manager's `local_rules.xml` file.

The detection logic used Wazuh field matching against Sysmon Event ID 1 process-creation telemetry or native Windows event data.

Before testing, the Wazuh configuration was checked using:

```text
wazuh-analysisd -t
```

This was used to verify that the rules could be loaded without configuration errors.

---

# Rule 100400 — Scheduled Task

## MITRE ATT&CK

**Technique:** T1053.005 — Scheduled Task

**Tactic:** Persistence

**Wazuh Level:** 8

## Detection Objective

Detect scheduled-task creation using `schtasks.exe` when the `/create` argument appears in the command line.

## Detection Logic

The rule looks for:

```text
schtasks.exe
```

with:

```text
/create
```

in the command line.

## Simulation

Atomic Red Team was used to simulate scheduled-task creation.

The test created two scheduled tasks:

```text
T1053_005_OnLogon
T1053_005_OnStartup
```

Both tasks were configured to launch `cmd.exe` when triggered.

## Result

**Successfully Fired**

The rule fired twice from the test because two scheduled tasks were created.

## Security Significance

Scheduled tasks are legitimate Windows functionality, but attackers can also abuse them to establish persistence or execute commands automatically.

## Triage Consideration

The analyst should investigate:

- Task name
- Task creator
- Command executed
- Trigger type
- Parent process
- Whether the task was authorized

## Detailed Documentation

[View Rule 100400](rule-100400.md)

---

# Rule 100401 — Clear Windows Event Logs

## MITRE ATT&CK

**Technique:** T1070.001 — Clear Windows Event Logs

**Tactic:** Defense Evasion

**Wazuh Level:** 12

## Detection Objective

Detect the clearing of the Windows Security audit log.

## Detection Logic

The rule monitors Windows Security Event ID:

```text
1102
```

Windows Event ID 1102 indicates that the Security audit log was cleared.

The core detection condition is:

```xml
<field name="win.system.eventID">1102</field>
```

## Simulation

The installed Atomic Red Team library did not contain a maintained test case for T1070.001.

The underlying behavior was therefore reproduced manually in the isolated lab using:

```text
wevtutil cl Security
```

## Result

**Successfully Fired**

The Wazuh alert successfully detected the Security audit log clearing activity.

The alert included the account associated with the activity.

## Security Significance

Attackers may clear security logs to remove evidence of their activity.

This makes log-clearing behavior particularly relevant to defense-evasion and anti-forensics detection.

## Evidence

![Rule 100401 - Clear Windows Event Logs](../evidence/rule-100401-cleared-logs.png)

## Detailed Documentation

[View Rule 100401](rule-100401.md)

---

# Rule 100402 — System Information Discovery

## MITRE ATT&CK

**Technique:** T1082 — System Information Discovery

**Tactic:** Discovery

**Wazuh Level:** 5

## Detection Objective

Detect execution of:

```text
systeminfo.exe
```

## Detection Logic

The rule monitors process-creation telemetry for `systeminfo.exe`.

## Simulation

Atomic Red Team was used to simulate system information discovery.

The resulting telemetry showed execution of `systeminfo.exe`.

The parent command line also showed `systeminfo` chained with a registry query, consistent with a scripted reconnaissance step.

## Result

**Successfully Fired**

The rule fired on the first attempt.

## Security Significance

System information discovery can help an attacker understand the operating system and environment of a compromised host.

## Triage Consideration

The analyst should review:

- User account
- Parent process
- Command line
- Related discovery commands
- Other activity from the same endpoint

## Evidence

![Rule 100402 - System Information Discovery](../evidence/rule-100402-systeminfo.png)

## Detailed Documentation

[View Rule 100402](rule-100402.md)

---

# Rule 100403 — System Owner/User Discovery

## MITRE ATT&CK

**Technique:** T1033 — System Owner/User Discovery

**Tactic:** Discovery

**Wazuh Level:** 5

## Detection Objective

Detect execution of:

```text
whoami.exe
```

## Detection Logic

The rule monitors process-creation telemetry for `whoami.exe`.

## Simulation

Atomic Red Team was used to simulate user discovery.

Testing included:

- Direct `whoami.exe` execution
- PowerShell-invoked `whoami.exe` execution

## Result

**Successfully Fired**

The rule fired five times across repeated testing.

Both direct and PowerShell-invoked executions were detected.

## Security Significance

User discovery can help an attacker determine the account context under which they are operating.

However, `whoami.exe` can also be used legitimately by administrators and scripts.

Therefore, context is important when investigating this alert.

## Triage Consideration

The analyst should review:

- User account
- Parent process
- Command line
- Execution context
- Related activity

## Evidence

![Rule 100403 - User Discovery](../evidence/rule-100403-whoami.png)

## Detailed Documentation

[View Rule 100403](rule-100403.md)

---

# Rule 100404 — LSASS Credential Dumping

## MITRE ATT&CK

**Technique:** T1003.001 — OS Credential Dumping: LSASS Memory

**Tactic:** Credential Access

**Wazuh Level:** 15 — Critical

## Detection Objective

Detect potential LSASS memory dumping through suspicious use of:

```text
rundll32.exe
comsvcs.dll
MiniDump
```

## Detection Logic

The rule looks for:

- `rundll32.exe`
- `comsvcs.dll`
- `MiniDump`

The detection is mapped to MITRE ATT&CK T1003.001.

## Simulation

The following controlled command was attempted:

```text
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 596 C:\Windows\Temp\lsass_test.dmp full
```

The test was attempted through both Atomic Red Team and direct manual execution.

## Result

**Blocked by Windows Defender**

The attempted execution returned:

```text
Access is denied
```

Windows Defender prevented the underlying behavior from executing.

Therefore, there was no successful live-fire execution from which the Wazuh detection could be directly validated.

## Security Significance

LSASS credential dumping is a high-risk credential-access technique because successful execution can expose authentication material stored in LSASS memory.

## Detection Engineering Finding

The rule was not modified simply to force the simulation to succeed.

The result was documented as an **endpoint prevention finding**.

This demonstrates the complementary relationship between:

```text
Endpoint Prevention
        +
SIEM Detection
        =
Layered Security Monitoring
```

## Detailed Documentation

[View Rule 100404](rule-100404.md)

---

# Rule 100405 — Ingress Tool Transfer

## MITRE ATT&CK

**Technique:** T1105 — Ingress Tool Transfer

**Tactic:** Command and Control

**Wazuh Level:** 10

## Detection Objective

Detect suspicious use of `certutil.exe` with the `-urlcache` argument.

## Detection Logic

The rule looks for:

```text
certutil.exe
```

combined with:

```text
-urlcache
```

## Simulation

A controlled certutil transfer attempt was performed.

The attempted command used `certutil` to retrieve a file from a remote URL.

## Result

**Blocked by Windows Defender**

The simulation was prevented before the expected transfer behavior could execute.

The attempt returned:

```text
Access is denied
```

Both the Atomic Red Team attempt and direct manual attempt were blocked.

## Security Significance

`certutil.exe` is a legitimate Windows utility but can also be abused to transfer files.

Monitoring suspicious use of the utility can therefore provide detection coverage for potential ingress tool transfer activity.

## Detection Engineering Finding

Because Windows Defender prevented the underlying behavior from executing, the Wazuh detection could not be validated through a successful live-fire transfer.

The rule was documented as **prevented/unvalidated against successful execution** rather than incorrectly claiming that it fired.

## Detailed Documentation

[View Rule 100405](rule-100405.md)

---

# Detection Validation Summary

## Overall Results

| Category | Rules | Count |
|---|---|---:|
| Successfully Fired | 100400, 100401, 100402, 100403 | **4** |
| Blocked by Windows Defender | 100404, 100405 | **2** |
| Total | 100400–100405 | **6** |

## Result

**4 of 6 rules were successfully validated against live simulated telemetry.**

**2 of 6 simulations were prevented by Windows Defender.**

The two prevented simulations were treated as endpoint security-control findings rather than detection failures.

---

# Detection Data Sources

The rules primarily relied on:

### Sysmon

Sysmon process-creation telemetry was used for detections involving:

- Scheduled tasks
- System information discovery
- User discovery
- LSASS dumping
- Certutil execution

### Windows Security Events

Native Windows Security event data was used for the Windows Security audit-log clearing detection.

For Rule 100401, Windows Event ID `1102` was used as the observable indicator.

---

# Detection Engineering Lessons

This project demonstrated that detection engineering involves more than writing a rule.

A detection must connect:

```text
Attacker Behavior
        ↓
Observable Telemetry
        ↓
Detection Logic
        ↓
SIEM Alert
        ↓
Analyst Investigation
```

The testing process therefore included:

- Selecting ATT&CK techniques
- Identifying observable behaviors
- Creating Wazuh rules
- Validating the configuration
- Simulating activity
- Reviewing telemetry
- Confirming detection results
- Documenting limitations

---

# Important Validation Note

A blocked simulation should not automatically be interpreted as a failed detection.

For Rules **100404** and **100405**, Windows Defender prevented the targeted behaviors before the expected execution telemetry could be generated.

The project therefore documented two separate outcomes:

```text
Detection Validation
        +
Endpoint Prevention Validation
```

This distinction is important when evaluating SIEM detection coverage.

---

# Cleanup

Atomic Red Team cleanup procedures were executed after tests that created persistent artifacts.

A follow-up check confirmed that the scheduled tasks created during the T1053.005 test were removed from the Windows endpoint.

No residual scheduled-task state remained from the simulation.

---

# Related Documentation

- [Attack Simulation](../attack-simulation/README.md)
- [Alert Triage](../alert-triage/README.md)
- [MITRE ATT&CK Mapping](../mitre-attack/README.md)
- [Project Findings](../findings/README.md)
