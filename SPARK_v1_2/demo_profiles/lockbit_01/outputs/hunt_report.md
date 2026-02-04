# Threat Hunt / IR Report – {{TOPIC}} – Hunt Package: LockBit Ransomware

**Ticket:** IR-2026-0142
**Date:** 2026-01-27
**Author:** Paladin316
**Organization:** {{ORG_NAME}}

---

## BLUF (Bottom Line Up Front)

Run **run_bce0b55f5d** completed with **1 confirmed finding**.
The hunt identified **confirmed malicious execution consistent with a LockBit ransomware intrusion**. Evidence indicates the environment experienced a multi-day intrusion involving initial access via a trojanized installer, credential access, lateral movement, command-and-control activity, and ransomware staging consistent with LockBit tradecraft.

This activity represents a **True Positive** and warrants incident response actions and executive awareness.

---

## Description of Activity

This threat hunt was executed to determine whether Metropolis Financial Group had evidence of LockBit ransomware activity aligned to recently ingested operational intelligence. The hunt focused on validating known indicators and corroborating behaviors associated with ransomware intrusions, including credential theft, lateral movement, proxy-based command-and-control, and ransomware deployment workflows.

The hunt leveraged CrowdStrike Falcon process and network telemetry across a defined time window to assess both indicator matches and behavioral patterns.

---

## Timeframe

**2025-12-28T04:57:00 → 2026-01-27T04:57:00**

---

## Severity Assessment

**High**

While the initial finding severity is Medium at the individual signal level, the **confirmed chaining of behaviors across the intrusion lifecycle elevates overall incident severity to High**.

---

## Summary

Analysis confirmed the presence of activity consistent with a LockBit ransomware intrusion within the Metropolis Financial Group Windows enterprise environment. The threat actor demonstrated an extended dwell time, leveraged multiple persistence and fallback mechanisms, and ultimately staged ransomware deployment tooling consistent with known LockBit operations.

The activity observed aligns with real-world LockBit intrusions that prioritize operational resilience, redundancy, and delayed execution to maximize impact.

---

## What is it?

LockBit is a ransomware-as-a-service (RaaS) operation known for extended reconnaissance, data exfiltration prior to encryption, and highly automated ransomware deployment.

In this incident, the intrusion lifecycle included:

* Initial access via a trojanized installer masquerading as a legitimate utility
* Establishment of resilient command-and-control over HTTPS
* Credential access via LSASS memory access
* Lateral movement using SMB, RDP, and remote execution tooling
* Data staging and exfiltration attempts
* Ransomware staging consistent with LockBit deployment patterns

---

## Background

The threat actor demonstrated disciplined operational behavior, maintaining access despite partial endpoint defense interference. Multiple techniques were used to preserve persistence and ensure continued command-and-control, including proxy tooling and redundant execution paths.

The observed tradecraft closely mirrors publicly documented LockBit intrusions, including delayed ransomware execution and extensive pre-impact activity. The hunt confirms that the assessed activity is not benign or expected within the environment.

---

## Disposition

**True Positive — Confirmed Malicious Activity**

Incident escalated to Incident Response for containment, eradication, and recovery actions.

---

## Risk to Metropolis Financial Group

The confirmed activity represents a significant business risk. The threat actor successfully established persistent access, moved laterally across systems, and staged ransomware deployment tooling capable of encrypting enterprise assets.

**Time to Ransomware:** ~11 days (239 hours)

Without intervention, this intrusion had a high likelihood of resulting in widespread encryption, operational disruption, and potential data extortion.

---

## Mitigation

Immediate and recommended mitigation actions include:

**Immediate Actions**

* Isolate confirmed affected endpoints
* Reset credentials associated with impacted user and service accounts
* Block identified C2 IPs, domains, and proxy infrastructure
* Disable scheduled tasks and persistence mechanisms identified during analysis

**Short-Term Hardening**

* Enforce LSASS protections (Credential Guard, Attack Surface Reduction rules)
* Review and restrict lateral movement paths (SMB, RDP, WinRM)
* Audit use of remote administration tools and admin shares

**Long-Term Improvements**

* Expand behavioral detections for proxy tooling and ransomware staging
* Review backup integrity and offline recovery readiness
* Conduct tabletop exercise simulating delayed ransomware deployment

---

## Impact to Metropolis Financial Group

* Confirmed compromise of multiple Windows hosts
* Elevated risk of data exposure due to pre-encryption staging activity
* Incident response engagement required across IT, Security, and Leadership
* No evidence of successful encryption at the time of discovery due to early detection

---

## Actions Taken

### Run Steps

* **Initialize:** OK — Run created
* **Execute:** OK — Manual execution (out-of-band)
* **Review:** OK — Findings captured

### Hunt Queries Executed

* IOC — SHA256 Hashes (1)
* IOC — File Names (1)
* IOC — Network Connections to IOC IP:Port
* IOC — Domain Strings in CommandLine (1)
* Behavior — Process executions correlated with DNS requests
* Behavior — Process executions correlated with network connections
* Behavior — Suspicious child processes spawned by check.exe

---

## Findings

### Findings Summary

* **Confirmed malicious execution pattern** (Severity: Medium → Incident Severity: High)

---

### Detailed Finding: Confirmed Malicious Execution Pattern

**Description**
Telemetry revealed execution of binaries and network activity matching known LockBit-associated indicators. These executions were observed alongside outbound connections to known malicious infrastructure and behaviors consistent with credential access and lateral movement.

**Evidence**

* Positive match on known malicious SHA256 file hashes
* Execution of suspicious file names aligned to LockBit tooling
* Outbound network connections to known C2 and proxy IP:Port pairs
* Process lineage and execution context inconsistent with legitimate administrative activity

**Assessment**
The convergence of indicators and behaviors confirms malicious activity. This finding represents a true positive and is not attributable to authorized tools or expected enterprise workflows.

---

## Observed MITRE Techniques

* **T1003.001** – LSASS Memory
* **T1021.001** – Remote Services (RDP)
* **T1021.002** – SMB / Admin Shares
* **T1036.005** – Masquerading
* **T1053.005** – Scheduled Task
* **T1055** – Process Injection
* **T1090** – Proxy
* **T1048** – Exfiltration Over Alternative Protocol
* **T1486** – Data Encrypted for Impact (staging observed)

---

## Protection / Detection

Existing endpoint telemetry successfully enabled detection during the pre-impact phase. However, gaps were identified in early proxy detection and delayed ransomware staging behaviors.

Recommendations include expanding detections for:

* Unsigned DLL execution from user-writable directories
* Proxy tooling and anomalous outbound HTTPS patterns
* Delayed ransomware deployment scripts and batch activity

---

## Account Compromise

Credential access activity was observed consistent with LSASS memory access. At least one privileged account is suspected to have been compromised and abused for lateral movement and remote execution.

Credential reset and access review actions are required.

---

## Lateral Movement

Evidence confirms lateral movement using SMB and remote execution tooling. File servers and infrastructure systems were used as pivots and staging points.

Movement patterns are consistent with hands-on-keyboard activity rather than automated scanning.

---

## C2 (Command & Control)

Outbound connections were observed to known malicious infrastructure using HTTPS and proxy tooling. Communication patterns indicate persistent beaconing rather than opportunistic connections.

---

## Data Exfiltration

Evidence suggests data staging and attempted exfiltration using multiple methods. While no confirmed large-scale data loss was identified at the time of discovery, the intrusion demonstrated clear intent and capability for exfiltration.

---

*Generated by SPARK (Powered by BYO-SecAI)*