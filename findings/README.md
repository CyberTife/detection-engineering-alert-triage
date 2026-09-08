Findings
Executive Summary

This project evaluated the ability of Wazuh to detect and support the triage of endpoint activities mapped to the MITRE ATT&CK framework.

Six custom Wazuh detection rules were developed and tested against simulated attack techniques. Four techniques successfully generated Wazuh alerts, while two techniques were prevented by Windows Defender before the expected behavior could execute.

The project demonstrated the importance of combining detection engineering, endpoint telemetry, attack simulation, alert triage, and security controls such as Windows Defender.

Key Results
Metric	Result
Custom Wazuh rules developed	6
Detection scenarios tested	6
Successfully validated detections	4
Defender-prevented scenarios	2
ATT&CK techniques covered	6
Primary endpoint	Windows
SIEM	Wazuh 4.14.6
Endpoint telemetry	Sysmon
Attack simulation	Atomic Red Team + manual reproduction
Successfully Validated Detections

The following four detection rules successfully generated Wazuh alerts during testing.

Rule 100400 — Scheduled Task Creation

MITRE ATT&CK: T1053.005 — Scheduled Task/Job: Scheduled Task
Tactic: Persistence

The rule successfully detected scheduled task creation using schtasks.exe.

Two test tasks were created during simulation:

T1053_005_OnLogon
T1053_005_OnStartup

The resulting Windows activity generated Wazuh alerts, demonstrating that the rule could identify scheduled-task activity associated with persistence.

Rule 100401 — Clear Windows Event Logs

MITRE ATT&CK: T1070.001 — Indicator Removal: Clear Windows Event Logs
Tactic: Defense Evasion

The expected Atomic Red Team test was not available in the installed test library, so the behavior was manually reproduced using:

wevtutil cl Security

The activity generated Windows Security Event ID 1102, which was successfully detected by Wazuh Rule 100401.

This demonstrated that the detection could identify an attempt to remove security event-log evidence.

Rule 100402 — System Information Discovery

MITRE ATT&CK: T1082 — System Information Discovery
Tactic: Discovery

The rule successfully detected execution of systeminfo.exe.

The generated telemetry showed system-information discovery activity and demonstrated that Wazuh could identify reconnaissance commands executed against the Windows endpoint.

Rule 100403 — System Owner/User Discovery

MITRE ATT&CK: T1033 — System Owner/User Discovery
Tactic: Discovery

The rule successfully detected whoami.exe execution.

The test generated multiple alerts, including activity executed directly and through PowerShell.

This demonstrated the ability of the detection to identify user-account discovery activity from endpoint telemetry.

Defender-Prevented Detections

Two detection scenarios could not be fully validated through live execution because Windows Defender prevented the simulated behavior.

Rule 100404 — LSASS Credential Dumping

MITRE ATT&CK: T1003.001 — OS Credential Dumping: LSASS
Tactic: Credential Access

The test attempted to use rundll32.exe with comsvcs.dll and the MiniDump functionality to simulate LSASS memory dumping.

Windows Defender prevented the activity, resulting in an Access is denied condition.

The test was also manually reproduced with the same defensive result.

The detection rule was therefore not weakened or modified simply to force the attack to execute.

Finding: The endpoint security control successfully prevented the simulated credential-access behavior.

Rule 100405 — Ingress Tool Transfer

MITRE ATT&CK: T1105 — Ingress Tool Transfer
Tactic: Command and Control

The test attempted to use certutil.exe with the -urlcache option to simulate downloading a file to the endpoint.

Windows Defender blocked the activity with an Access is denied result.

A manual reproduction produced the same result.

Finding: The endpoint security control prevented the simulated file-transfer activity before the expected behavior could be fully executed.

Alert Triage Findings

Alert triage was performed using the following workflow:

Validate → Identify → Investigate → Classify → Prioritize → Escalate or Close → Document

The triage exercises included both real alerts generated during testing and constructed scenarios representing potential false positives.

Triage Outcomes
Outcome	Result
Alerts exercised	6
Escalated alerts	2
Immediate containment cases	1
Monitored/prevented cases	2
Verified false positives closed	2

The exercises demonstrated that an alert should not automatically be treated as malicious simply because a suspicious command or technique was detected.

Context, user activity, process information, timing, and the surrounding environment must be considered before making a final classification.

False-Positive Findings

Two false-positive scenarios were used to demonstrate contextual alert analysis.

Linux Inventory Activity

A whoami execution was associated with a documented Linux inventory process and a recognized service account.

Although the command matched a discovery technique, the surrounding context indicated legitimate administrative activity.

Classification: False Positive / Benign Expected Activity

Windows Update Activity

A SYSTEM-created scheduled task occurred during a confirmed Windows Update window.

Although scheduled-task creation can be associated with persistence, the timing and context matched legitimate operating-system activity.

Classification: False Positive / Benign Expected Activity

Detection Tuning Findings

The four successfully firing detection rules did not require tuning during this project.

The two Defender-blocked rules were also not weakened simply to obtain successful attack execution.

This preserved the security value of the detection logic and demonstrated an important SOC principle:

Detection engineering should improve visibility without unnecessarily reducing security controls.

The Linux static-IP issue encountered during the project was treated as an infrastructure problem rather than a detection-rule problem. The issue was traced to cloud-init/netplan configuration and corrected.

Key Challenges and Gaps
1. Windows-Centric Simulation

The attack simulations primarily targeted the Windows endpoint.

This limited validation of the detection rules across different operating systems and highlighted the need for broader cross-platform testing.

2. Atomic Red Team Test Availability

The installed Atomic Red Team library did not contain a maintained test for T1070.001.

The behavior was therefore manually reproduced using the appropriate Windows command.

3. Defender Prevention

Windows Defender prevented the LSASS dumping and certutil transfer simulations.

This meant that Rules 100404 and 100405 were not fully validated through successful live-fire execution.

However, the prevention itself provided useful evidence that endpoint security controls were functioning as intended.

4. Lab Infrastructure Stability

The Linux endpoint lost its static host-only IP configuration after shutdown.

Investigation identified cloud-init/netplan configuration as the cause, and the network configuration was corrected.

Cleanup and Validation

After testing:

Scheduled-task test artifacts were removed.
Test artifacts were verified as cleaned up.
The lab environment was restored.
Detection rules were reviewed.
Defender protections were not disabled to force blocked simulations to succeed.

Cleanup ensured that the lab did not retain unnecessary test artifacts after the exercises.

Lessons Learned

This project demonstrated several important SOC and detection-engineering principles:

A detection rule must be validated against real telemetry.
Not every alert represents malicious activity.
Alert context is essential for accurate triage.
Security controls can prevent attack simulations before detection occurs.
Blocked attacks can still provide valuable security findings.
Detection rules should not be weakened simply to increase test success.
MITRE ATT&CK provides a useful framework for organizing detection coverage.
Effective SOC analysis requires both technical investigation and contextual reasoning.
Infrastructure problems can affect security-lab testing and must be investigated separately from detection logic.
Detection engineering should be continuously tested and improved.
Future Improvements

Future iterations of the project could include:

Additional Windows detection rules.
More Linux-focused detection scenarios.
Cross-platform validation of detection logic.
Additional Atomic Red Team simulations.
More complex attack chains.
Continuous detection-rule tuning.
Alert correlation across multiple events.
Development of a living SOC triage playbook.
Additional endpoint telemetry sources.
More advanced investigation and escalation scenarios.
Conclusion

The project successfully demonstrated an end-to-end detection engineering and alert triage workflow using Wazuh, Windows endpoint telemetry, Sysmon, Atomic Red Team, and MITRE ATT&CK.

Four of the six detection scenarios were successfully validated, while two were prevented by Windows Defender. The results showed that effective SOC monitoring is not limited to generating alerts; analysts must also validate, investigate, classify, prioritize, and document security events.

The project provided practical experience in building detections, analyzing endpoint telemetry, understanding MITRE ATT&CK techniques, handling prevented attacks, identifying false positives, and making SOC escalation decisions.

Related Project Sections
Detection Rules
Attack Simulation
Alert Triage
MITRE ATT&CK Mapping
Project Overview
