# Security Policy

SPARK is a local-first, analyst-driven platform designed to help security practitioners translate intelligence into hunts, findings, and detection strategies. Security and transparency are core goals of the project.

This document explains how to report vulnerabilities, what is in scope, and how SPARK approaches AI safety risks such as prompt injection.

---

## Supported Versions

SPARK is currently in active development.

Security fixes will generally be applied to:
- The latest release, and
- The main branch (until the next release)

If you are running an older version, upgrade to the latest release before reporting suspected security issues unless you believe the issue prevents upgrading.

---

## Reporting a Vulnerability

If you believe you’ve found a security vulnerability in SPARK, please report it responsibly.

**Preferred method**
- Open a **GitHub Security Advisory** (Private Vulnerability Report), if enabled for the repository.

**If private reporting is not available**
- Open a GitHub Issue with the title prefix: **[SECURITY]**
- **Do not** include exploit code, secrets, tokens, or sensitive data in a public issue.
- If you must include proof-of-concept details, provide high-level reproduction steps and offer to share additional detail privately.

**What to include**
- A clear description of the issue and impact
- Steps to reproduce (as safely as possible)
- Affected version(s) / commit hash
- Operating system and runtime details
- Logs or screenshots (redacted)

---

## Response Targets

SPARK is maintained as an open-source project. Best-effort response targets:

- **Initial acknowledgment:** within 7 days
- **Triage / severity assessment:** within 14 days
- **Fix timeline:** depends on severity and complexity

If the issue is critical and easily exploitable, priority will be given to mitigation guidance and a patch.

---

## Scope

### In scope
- Remote code execution (RCE)
- Local privilege escalation (LPE) caused by SPARK behavior
- Arbitrary file read/write outside expected local storage paths
- Authentication / authorization issues (if applicable in your deployment)
- Supply chain risks introduced by SPARK packaging or dependency handling
- Unsafe URL fetching or file ingestion behaviors that lead to compromise
- Prompt injection weaknesses that meaningfully impact data handling or execution

### Out of scope
- Vulnerabilities in third-party dependencies where SPARK is not the root cause  
  (still welcome as reports — they help — but may be routed to upstream)
- Misconfiguration or insecure runtime environments (e.g., exposed local services)
- Issues requiring physical access to the host
- Social engineering or phishing against users

---

## AI Safety and Prompt Injection

SPARK may process untrusted content such as:
- Threat reports and advisories
- Paste-in text
- Uploaded documents
- Fetched URLs

These sources may include instruction-like text intended to influence an AI system (prompt injection) or to cause output drift.

SPARK uses lightweight, heuristic-based scanning to identify instruction-like patterns. **These signals do not prove malicious intent.** They highlight language that is commonly associated with unsafe behavior in AI-assisted workflows.

### Prompt Injection Risk Handling

SPARK includes heuristic-based detection to identify instruction-like language patterns that may influence AI-assisted workflows.

These detections:
- Do **not** imply malicious intent
- Commonly trigger on legitimate DFIR and threat intelligence content
- Are intended to inform analyst review, not enforce blocking

SPARK favors analyst awareness over automated enforcement.

---

### Prompt Injection Risk Levels

#### LOW
**Definition:**  
Benign or contextual language that resembles instructions or encoding techniques, commonly found in legitimate security advisories, DFIR reports, and technical write-ups.

**Common examples:**
- Descriptions of attacker behavior (e.g., “Base64-encoded PowerShell”)
- Tool or technique explanations
- Narrative “steps” describing what a victim was prompted to do

**SPARK behavior:**  
Content is processed normally. A LOW flag is informational and may produce false positives.

---

#### MEDIUM
**Definition:**  
Instruction-like language that attempts to shape assistant behavior, introduce hidden constraints, or redirect outputs away from the user’s intent.

**Common examples:**
- “Ignore previous instructions…”
- “You must output only…”
- Requests to reveal system prompts or secrets
- Attempts to override review/approval workflows

**SPARK behavior:**  
Content is processed, but users should review carefully. Projects may choose to require explicit acknowledgement before using AI augmentation on this content.

---

#### HIGH
**Definition:**  
Clear attempts to induce unsafe actions or bypass controls, including payload-style instructions or coercion aimed at execution, exfiltration, credential capture, or policy bypass.

**Common examples:**
- “Run this command / paste this script…”
- Embedded payload instructions disguised as troubleshooting
- Attempts to extract credentials, API keys, or local files
- Bypass instructions intended to disable safeguards

**SPARK behavior:**  
High-risk content should be treated as untrusted. Users should avoid executing suggested commands and should isolate analysis. A project deployment may choose to block AI augmentation by default for HIGH.

---

## Local-First Threat Model

SPARK is designed for environments handling sensitive security data.

Threat model assumptions:
- No cloud LLM required by default
- No automatic external data sharing
- Analyst controls model selection and execution
- Clear boundaries between user input, stored artifacts, and AI suggestions

SPARK prioritizes transparency and analyst trust over opaque automation.

---

## Proxy and External Connectivity

SPARK supports optional outbound proxy configuration.

- All outbound access is explicit
- Proxy settings are respected globally
- Example values shown in the UI are placeholders only

SPARK does not perform silent external network calls.

---

## Data Handling and Privacy Notes

SPARK is designed to be **local-first** by default.

- Artifacts are stored locally in project-defined paths (e.g., `./data/`)
- If you enable local model integration (e.g., Ollama), prompts and outputs remain on your host
- If you configure any external services (proxying, remote LLMs, URL fetch), you are responsible for understanding and accepting the data exposure tradeoffs

**Do not upload secrets** (API keys, credentials, proprietary data) unless you are operating in a controlled environment and understand the implications of your configuration.

---

## Safe Harbor

If you:
- Make a good-faith effort to avoid privacy violations and system disruption
- Only test against systems you own or have permission to test
- Report issues responsibly and allow reasonable time to address them

…then the project maintainers will not pursue legal action against you for your research.

---

## Security Hardening Recommendations

If you deploy SPARK in a shared environment:
- Restrict network exposure (bind to localhost, use access controls)
- Run as a non-admin user
- Treat all ingested content as untrusted
- Keep dependencies updated
- Use isolated environments for analyzing suspicious files (VM/container)

---

## Acknowledgements

Responsible disclosure improves SPARK for everyone. Thank you for helping make the project safer.
