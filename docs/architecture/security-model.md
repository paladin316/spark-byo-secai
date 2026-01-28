# SPARK Security Model

This document describes the **security design principles, trust boundaries, and threat assumptions** that guide SPARK’s architecture.

SPARK is not a traditional SaaS security product. It is a **local-first, analyst-driven analytical workbench**. As such, its security model prioritizes transparency, analyst control, and predictable behavior over opaque automation.

---

## Design Goals

SPARK’s security model is built around the following goals:

1. **Preserve analyst trust**
2. **Minimize implicit risk**
3. **Avoid hidden data movement**
4. **Make security-relevant behavior observable**
5. **Favor awareness over enforcement**

SPARK assumes that its users are security practitioners operating in environments where **understanding risk matters more than abstracting it away**.

---

## Core Security Principles

### 1. Local-First by Default

SPARK is designed to operate entirely on the analyst’s host system unless explicitly configured otherwise.

- Artifacts are stored locally
- AI models are local by default
- No background telemetry or analytics
- No implicit cloud dependencies

This allows SPARK to be used safely with:
- Incident response data
- Internal threat intelligence
- Sensitive investigative material

---

### 2. Analyst-in-the-Loop

SPARK does not make autonomous security decisions.

Key actions always require analyst intent or approval, including:
- Intel Brief approval
- Hunt Package generation
- Finding creation
- Detection Strategy authoring

AI output is advisory and **never authoritative**.

---

### 3. Explicit Trust Boundaries

SPARK defines clear trust boundaries between:

- **Untrusted input**  
  (uploaded documents, pasted text, fetched URLs)

- **Stored artifacts**  
  (Intel Briefs, Hunts, Findings, ADS)

- **AI augmentation**  
  (LLM prompts and outputs)

Untrusted input is never assumed to be safe, even when sourced from reputable vendors or government advisories.

---

## AI Security Model

### AI as an Augmentation Layer

SPARK uses AI to assist analysts with:
- Drafting
- Normalization
- Enrichment
- Translation of narrative content into structured artifacts

AI **does not**:
- Execute commands
- Modify the system
- Make enforcement decisions
- Override analyst workflows

All AI-generated content is reviewable and editable.

---

### Retrieval-Augmented Generation (RAG)

SPARK uses a Retrieval-Augmented Generation (RAG) approach to ground AI output in analyst-provided context.

Key guarantees:
- Retrieval scope is limited to local artifacts
- Outputs are derived from retrieved context
- General int
