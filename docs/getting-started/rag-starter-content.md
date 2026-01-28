# RAG Starter Content Guide

This document provides guidance on sourcing and organizing content for SPARK’s Retrieval-Augmented Generation (RAG) workflow.

SPARK does **not** ship with a preloaded knowledge base. Instead, users bring their own content to ensure AI assistance reflects their environment, tooling, and operational priorities.

---

## Purpose

The goal of RAG in SPARK is not to replace analyst judgment or provide generic answers. It is designed to:

- Ground AI suggestions in **reviewed, trusted material**
    
- Preserve **explainability and auditability**
    
- Support **repeatable, analyst-driven workflows**
    
- Avoid stale, mislicensed, or irrelevant intelligence
    

The quality of AI output is directly tied to the quality of content you ingest.

---

## What Makes Good RAG Content

Strong starter content typically shares these characteristics:

- **Operationally relevant** (used in real investigations or detections)
    
- **Written for analysts** (not marketing material)
    
- **Structured or semi-structured**
    
- **Explainable** (describes _why_, not just _what_)
    

---

## Recommended Content Categories

The following categories work well as initial RAG material. All ingestion is optional and user-controlled.

### Internal Content (Highest Value)

- Intel Briefs and threat assessments
    
- Threat hunt packages and hypotheses
    
- Findings and post-incident reports
    
- Detection strategy documentation
    
- Blue team playbooks and runbooks
    

This content anchors AI suggestions to your actual environment and processes.

---

### Open-Source Detection & Hunting Repositories

Public repositories can help bootstrap content, especially for labs or demos:

- Detection rule collections (e.g., behavior-based rules)
    
- Threat hunting query libraries
    
- Technique-focused research notes
    
- Adversary emulation or test case documentation
    

**Important:**  
Licenses vary. Review usage terms before ingestion. Treat this material as a starting point—not ground truth.

---

### Public Threat Intelligence & Research

Useful for context enrichment and narrative support:

- Government or CERT advisories
    
- Vendor technical blogs and whitepapers
    
- DFIR write-ups and postmortems
    
- MITRE ATT&CK technique descriptions
    

Avoid ingesting raw IOC feeds without context—they add little value to RAG reasoning on their own.

---

## What to Avoid Ingesting

The following content generally degrades RAG quality:

- Uncurated IOC dumps
    
- Marketing or sales material
    
- Outdated threat reports
    
- Low-signal automated feeds
    
- Content containing secrets, credentials, or sensitive data
    

Remember: RAG amplifies what you give it—good or bad.

---

## Suggested Organization (Optional)

While SPARK does not enforce structure, many users find value in organizing content by:

- **Artifact type** (intel, hunt, finding, detection)
    
- **Threat or campaign**
    
- **MITRE ATT&CK technique**
    
- **Tooling or data source**
    

Consistency improves retrieval quality and AI grounding.

---

## Safety & Governance Notes

- All content ingestion is **explicit and local**
    
- No automatic internet scraping is performed
    
- AI suggestions remain bounded by provided material
    
- Analysts retain full control over what is trusted, promoted, or discarded
    

SPARK intentionally separates **exploration** (Notebook Workspace) from **governed artifacts** (Platform Workspace).

---

## Final Notes

SPARK’s RAG model is a force multiplier—not a shortcut.  
Well-curated content enables AI to assist with clarity, consistency, and scale, while keeping analysts firmly in control.

---

## Example Starter Content Bundles

The following **starter bundles** illustrate how users may bootstrap RAG content in SPARK. These are **profiles**, not packaged datasets. Users select, source, and ingest content at their discretion.

### 🧪 Threat Hunting Starter Bundle

**Purpose:** Support hypothesis-driven hunts and exploratory analysis.

**Typical Content:**

- Threat hunt playbooks and notes
    
- Technique-focused research write-ups
    
- Behavioral detection queries
    
- Adversary tradecraft analyses
    
- DFIR case studies
    

**Best For:**  
Threat hunters, purple teamers, research-focused workflows.

---

### 🛡️ Detection Engineering Starter Bundle

**Purpose:** Improve consistency and explainability in detection strategy development.

**Typical Content:**

- Detection strategy documents
    
- Alert logic rationale and tuning notes
    
- Detection gap analyses
    
- ATT&CK technique mappings
    
- False positive and allow-list guidance
    

**Best For:**  
Detection engineers and teams operationalizing hunts into alerts.

---

### 🚨 Incident Response Starter Bundle

**Purpose:** Ground AI assistance in response context and investigative patterns.

**Typical Content:**

- Incident timelines and after-action reports
    
- Triage and escalation runbooks
    
- Containment and remediation playbooks
    
- Lessons learned documentation
    

**Best For:**  
Incident responders and on-call analysts.

---

### 🧭 Executive / Program Context Bundle (Optional)

**Purpose:** Add narrative and program-level context to reports and summaries.

**Typical Content:**

- Threat landscape summaries
    
- Risk assessments
    
- Executive briefs
    
- Program-level detection goals
    

**Best For:**  
Reporting, briefings, and leadership-facing artifacts.

---

> These bundles are illustrative. SPARK does not enforce profiles, schemas, or ingestion order. Analysts remain in full control of what content is trusted and promoted.