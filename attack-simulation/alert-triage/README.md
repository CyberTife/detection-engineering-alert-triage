# Alert Triage

This section documents the alert triage process used to analyze, classify, prioritize, and respond to security alerts generated during the Detection Engineering & Alert Triage project.

The goal was to demonstrate how a SOC analyst can determine whether an alert represents malicious activity, legitimate activity, or activity that was prevented before completion.

## Objective

The alert triage phase focused on:

- Validating security alerts
- Identifying the source and nature of the activity
- Investigating relevant endpoint telemetry
- Determining whether the activity was malicious or legitimate
- Assigning an appropriate severity
- Prioritizing alerts based on risk
- Determining whether escalation or closure was required
- Documenting the investigation and final disposition

## SOC Alert Triage Workflow

The following workflow was used throughout the project:

**Validate → Identify → Investigate → Classify → Prioritize → Escalate or Close → Document**

Each stage provides a structured approach to handling security alerts.

## 1. Validate

The first step was to confirm that the alert was generated from actual endpoint activity.

Validation included reviewing:

- Wazuh rule ID
- Alert timestamp
- Endpoint hostname
- Username
- Process name
- Command line
- Event ID
- Parent process
- MITRE ATT&CK technique
- Available endpoint telemetry

The objective was to establish whether the alert represented a real event rather than an incorrectly generated alert.

## 2. Identify

After validating the event, the activity was identified by examining the behavior associated with the alert.

Examples included:

- Scheduled task creation
- Windows event-log clearing
- System information discovery
- User discovery
- Attempted LSASS credential dumping
- Attempted ingress tool transfer

The identified behavior was then mapped to its corresponding MITRE ATT&CK technique.

## 3. Investigate

Investigation involved examining the available telemetry to understand what occurred.

The investigation considered:

- What process executed?
- Which user executed it?
- What command line was used?
- Which endpoint generated the event?
- Was the behavior expected?
- Was the behavior blocked?
- Was there evidence of additional suspicious activity?

Wazuh and endpoint telemetry were used as the primary sources of investigation data.

## 4. Classify

After investigation, alerts were assigned a classification.

| Classification | Meaning |
|---|---|
| True Positive | Activity was confirmed to be suspicious or malicious |
| False Positive | Alert was triggered but the activity was not malicious |
| Benign / Expected | Activity was legitimate and expected in the environment |
| Prevented | The attempted behavior was blocked before successful execution |

Classification helped determine the appropriate response.

## 5. Prioritize

Alerts were prioritized according to their severity and potential security impact.

| Wazuh Level | Severity |
|---:|---|
| 1–4 | Low |
| 5–7 | Medium |
| 8–11 | High |
| 12–15 | Critical |

Higher-severity alerts required greater attention and faster investigation.

# Alert Triage Exercises

The triage exercises included:

- Four alerts based on actual fired or prevented detection scenarios
- Two constructed false-positive scenarios

The purpose was to demonstrate that a SOC analyst must investigate alerts rather than automatically treating every alert as malicious.

## Triage Exercise 1 — Scheduled Task

**Rule:** 100400

**Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task

### Activity

A scheduled task was created during the attack simulation.

The behavior generated a Wazuh alert associated with Rule 100400.

### Investigation

The alert was reviewed to determine:

- Which process created the task
- The task name
- The command associated with the task
- The account responsible for the activity
- Whether the activity was expected

### Classification

**True Positive**

The activity represented a simulated persistence technique.

### Priority

**High**

### Response

The alert was escalated for further investigation.

The test task was subsequently removed during lab cleanup.

## Triage Exercise 2 — Windows Event Log Clearing

**Rule:** 100401

**Technique:** T1070.001 — Indicator Removal: Clear Windows Event Logs

### Activity

The Windows Security event log was cleared using the `wevtutil` utility.

This generated Windows Security Event ID 1102.

### Investigation

The Wazuh alert was reviewed and correlated with the endpoint activity.

The event was associated with the clearing of the Windows Security audit log.

### Classification

**True Positive**

### Priority

**Critical**

Clearing security logs can represent an attempt to remove evidence of malicious activity.

### Response

The alert was escalated for further investigation and immediate containment consideration.

## Triage Exercise 3 — System Information Discovery

**Rule:** 100402

**Technique:** T1082 — System Information Discovery

### Activity

The `systeminfo.exe` process was executed.

### Investigation

The alert was examined for:

- Process name
- Command line
- Parent process
- Endpoint
- User context
- Related activity

The parent command line also provided additional context around the reconnaissance activity.

### Classification

**True Positive**

The activity was generated intentionally as part of the detection simulation.

### Priority

**Medium**

### Response

The alert was documented and monitored as part of the controlled lab exercise.

## Triage Exercise 4 — User Discovery

**Rule:** 100403

**Technique:** T1033 — System Owner/User Discovery

### Activity

The `whoami.exe` process was executed.

The simulation generated multiple alerts.

### Investigation

The analyst reviewed the execution context and observed that the activity occurred through both direct and PowerShell-invoked execution.

### Classification

**True Positive**

The behavior was intentionally generated during testing.

### Priority

**Medium**

### Response

The alert was documented and monitored as part of the simulation.

## Triage Exercise 5 — LSASS Credential Dumping Attempt

**Rule:** 100404

**Technique:** T1003.001 — OS Credential Dumping: LSASS Memory

### Activity

An LSASS memory-dumping technique was attempted.

### Investigation

The endpoint security control prevented the attempted behavior.

The execution returned an access-denied result.

Windows Defender prevented the intended credential-dumping activity from completing.

### Classification

**Prevented**

### Priority

**Critical**

The attempted behavior represented a credential-access technique with potentially significant security impact.

### Response

The event was treated as a security-relevant prevention event and documented for investigation.

The endpoint security control was not disabled to force successful execution.

## Triage Exercise 6 — Ingress Tool Transfer Attempt

**Rule:** 100405

**Technique:** T1105 — Ingress Tool Transfer

### Activity

A `certutil.exe` command associated with the attempted transfer behavior was executed.

### Investigation

Windows Defender prevented the activity.

The attempted execution returned an access-denied result.

### Classification

**Prevented**

### Priority

**High**

The attempted behavior was security-relevant because ingress tool transfer can be used by attackers to introduce tools or files into a compromised environment.

### Response

The event was documented as a prevented security event.

# False Positive Analysis

Two additional scenarios were constructed to demonstrate false-positive analysis.

The purpose was to show how legitimate administrative or system activity can resemble attacker behavior.

## False Positive 1 — User Discovery During Inventory

**Detection:** T1033 — System Owner/User Discovery

### Observed Activity

A `whoami` command was generated by a documented Linux inventory cron job using a recognized service account.

### Investigation

The analyst reviewed:

- Account
- Execution context
- Scheduled activity
- Expected inventory process
- Timing of the event

The activity was consistent with the documented inventory process.

### Classification

**False Positive / Benign Expected Activity**

### Response

The alert was closed after verification.

No escalation was required.

## False Positive 2 — Scheduled Task During Windows Update

**Detection:** T1053.005 — Scheduled Task/Job: Scheduled Task

### Observed Activity

A scheduled task was created by the SYSTEM account during a confirmed Windows Update window.

### Investigation

The analyst reviewed:

- Creating account
- Task timing
- Windows Update activity
- Expected system behavior

The activity was consistent with legitimate Windows Update operations.

### Classification

**False Positive / Benign Expected Activity**

### Response

The alert was closed after verification.

No escalation was required.

# Triage Summary

| Scenario | Rule | Classification | Priority | Disposition |
|---|---:|---|---|---|
| Scheduled Task | 100400 | True Positive | High | Escalated |
| Clear Windows Logs | 100401 | True Positive | Critical | Containment / Escalation |
| System Information Discovery | 100402 | True Positive | Medium | Monitored |
| User Discovery | 100403 | True Positive | Medium | Monitored |
| LSASS Dump Attempt | 100404 | Prevented | Critical | Documented / Monitored |
| Ingress Tool Transfer | 100405 | Prevented | High | Documented / Monitored |
| Inventory `whoami` | T1033 | False Positive | — | Closed |
| Windows Update Task | T1053.005 | False Positive | — | Closed |

# Escalation Decisions

Two alerts were identified as requiring escalation during the triage exercises.

### 1. Scheduled Task Persistence

The scheduled-task alert represented a persistence technique and required further investigation.

### 2. Windows Event Log Clearing

The event-log clearing alert received the highest severity because clearing security logs can indicate an attempt to remove evidence.

The latter also warranted immediate containment consideration.

# Key Triage Lessons

This project demonstrated several important SOC analyst principles.

### Alerts are not automatically incidents

A SIEM alert is an indicator that requires investigation. Analysts must determine what actually happened before deciding on a response.

### Context matters

Process name alone is not always sufficient.

The analyst should consider:

- User
- Parent process
- Command line
- Timestamp
- Endpoint
- Event ID
- Related activity
- Expected administrative behavior

### Prevention and detection are different

An endpoint security product can prevent an attack before the SIEM receives the telemetry required for a successful detection.

### False positives require investigation

Legitimate administrative and system activity can trigger rules that resemble attacker behavior.

### Documentation is part of triage

A SOC analyst should record the reasoning behind the classification and response decision.

# Analyst Takeaway

The alert triage phase helped me understand that SOC analysis is not simply about finding alerts.

The analyst must determine:

- What happened?
- Why did it happen?
- Who or what initiated it?
- Is it malicious, legitimate, or prevented?
- How serious is it?
- What should happen next?

This structured approach helps turn raw SIEM alerts into actionable security decisions.

## Next Step

The next section documents how the detection scenarios were mapped to the MITRE ATT&CK framework.

[MITRE ATT&CK Mapping](../mitre-attack/README.md)
