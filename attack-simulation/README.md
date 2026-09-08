# Attack Simulation

This section documents the attack simulation and validation activities performed during the Detection Engineering & Alert Triage project.

The simulations were conducted in an isolated lab environment using Atomic Red Team where applicable, with manual reproduction used for behaviors that could not be directly executed through the installed Atomic Red Team test library.

## Objective

The objective of the attack simulation phase was to:

- Generate representative adversary behaviors in a controlled environment
- Validate that custom Wazuh detection rules correctly identified those behaviors
- Map simulated activity to MITRE ATT&CK techniques
- Observe how endpoint security controls affected attack execution
- Generate alerts for subsequent SOC triage
- Document successful detections and security-control prevention

## Lab Environment

| Component | Purpose |
|---|---|
| Wazuh 4.14.6 | SIEM and alert analysis |
| Windows Endpoint | Primary attack simulation target |
| Sysmon | Windows endpoint telemetry |
| Atomic Red Team | Adversary behavior simulation |
| Windows Defender | Endpoint security control |
| Linux Endpoint | Supporting lab environment |
| Simulated Firewall | Network security component |

The existing cybersecurity lab environment was reused for this project.

## Simulation Methodology

The testing process followed this workflow:

1. Select a MITRE ATT&CK technique
2. Identify the detection requirement
3. Create or validate the Wazuh rule
4. Execute the simulation
5. Generate endpoint telemetry
6. Allow Wazuh to process the event
7. Validate the resulting alert
8. Perform alert triage
9. Document the result

Each detection scenario was evaluated based on whether the expected behavior generated the corresponding Wazuh alert.

## Techniques Tested

| Rule ID | MITRE Technique | Technique Name | Result |
|---|---|---|---|
| 100400 | T1053.005 | Scheduled Task/Job: Scheduled Task | Detected |
| 100401 | T1070.001 | Indicator Removal: Clear Windows Event Logs | Detected |
| 100402 | T1082 | System Information Discovery | Detected |
| 100403 | T1033 | System Owner/User Discovery | Detected |
| 100404 | T1003.001 | OS Credential Dumping: LSASS Memory | Prevented |
| 100405 | T1105 | Ingress Tool Transfer | Prevented |

### Overall Result

Four of the six scenarios successfully generated and validated Wazuh detections.

The remaining two scenarios were blocked by Windows Defender before the intended malicious behavior could fully execute.

These prevention results were retained as valid security findings rather than weakening endpoint security controls to force successful execution.

## Scenario 1 — Scheduled Task

### MITRE ATT&CK

**T1053.005 — Scheduled Task/Job: Scheduled Task**

### Detection Rule

**Rule ID: 100400**

### Simulation

The scheduled-task behavior was simulated using `schtasks.exe`.

Example command:

```powershell
schtasks.exe /create /tn T1053_005_OnLogon /tr "cmd.exe /c whoami" /sc onlogon
