# Source-agnostic Behavior Mapping Examples

These examples show the same extraction logic working across different intel formats.

## 1) Short advisory (CISA-style)
**Text:** "Threat actors used PowerShell to download and execute a payload, then established command and control over HTTPS."

**Behaviors extracted:**
- PROCESS_EXECUTION (powershell) with anchors: file/url strings if present
- DOWNLOAD with anchors: url
- OUTBOUND_C2 with anchors: https / domain / ip:port if present
- sequence_hint=True (then)

## 2) Vendor blog (tool-centric write-up)
**Text:** "The attacker leveraged PsExec for lateral movement and used Rclone to exfiltrate data to Mega."

**Behaviors extracted:**
- LATERAL_MOVEMENT via psexec (high confidence)
- EXFILTRATION via rclone (high confidence) with anchors: tools=[rclone], domains=[mega.io]

## 3) DFIR report / incident timeline (procedural)
**Text:** "After initial access, the adversary executed setup_wm.exe and shortly after beaconed to 159.100.14.254:443."

**Behaviors extracted:**
- PROCESS_EXECUTION with anchors: file_names=[setup_wm.exe], sequence_hint=True
- OUTBOUND_C2 with anchors: ip_ports=[159.100.14.254:443], sequence_hint=True

## 4) Malware analysis note (reverse engineering summary)
**Text:** "The sample creates a scheduled task for persistence and injects into a remote process before contacting C2."

**Behaviors extracted:**
- PERSISTENCE with anchors: scheduled task keywords (verb-driven)
- OUTBOUND_C2 (verb-driven)
- (Injection can be added in v2 when module/remote-thread telemetry is enabled.)

## How this proves source-agnostic design
- No single report format is required.
- Extraction is driven by universal verb patterns, common tool keywords, and sequencing language.
- Anchors are always expressed in telemetry-friendly categories (files/domains/urls/ip_ports/tools).
