# MCP Integrations in SPARK

This document describes the intended role of **Model Context Protocol (MCP)** integrations within SPARK.

MCP support in SPARK is designed to provide **structured context** to analyst-driven workflows — not to automate actions or delegate decision-making.

---

## Purpose

SPARK operates on the principle that analysts remain responsible for:
- Interpretation
- Approval
- Judgment
- Final decisions

MCP integrations exist to **expose external context in a structured, predictable way** so that AI-assisted features can operate with better grounding, consistency, and transparency.

MCP is used as a *context transport mechanism*, not an execution framework.

---

## What MCP Is Used For

If implemented, MCP servers may be used to:

- Retrieve structured metadata from external tools
- Normalize domain-specific concepts (e.g., techniques, fields, query syntax)
- Provide read-only reference material to AI-assisted workflows
- Reduce manual copy/paste and translation effort for analysts

Examples include:
- Mapping MITRE ATT&CK techniques to Atomic Red Team test definitions
- Providing Splunk schema or query structure context for query drafting
- Enriching threat hunt artifacts with externally sourced, non-executing metadata

---

## What MCP Is Not Used For

To preserve SPARK’s analyst-driven design, MCP integrations will **not**:

- Execute Atomic Red Team tests
- Run Splunk searches automatically
- Trigger detections, alerts, or response actions
- Modify external systems
- Bypass SPARK approval gates or validation workflows
- Act as autonomous agents or decision-makers

Any execution or action remains an explicit analyst responsibility, outside of MCP.

---

## Design Principles

MCP integrations in SPARK follow these constraints:

### 1. Analyst Control
All MCP usage is explicitly enabled by the user.  
No MCP server is required for SPARK to function.

### 2. Read-Only by Default
MCP servers expose context and metadata, not execution capability.

### 3. Non-Authoritative
External context is informative, not a source of truth.  
SPARK artifacts remain analyst-owned and locally stored.

### 4. Guardrail Preservation
MCP integrations cannot bypass:
- Intel approval requirements
- Hunt package validation
- Finding and ADS review steps

### 5. Local-First Compatibility
MCP servers may run locally or in controlled environments, consistent with SPARK’s local-first design.

---

## Example MCP Integrations

### Atomic Red Team (Conceptual)

An Atomic Red Team MCP server could provide:
- Technique-to-test mappings
- Test descriptions and prerequisites
- Expected telemetry and outcomes

This enables SPARK to:
- Assist with hunt hypothesis formulation
- Provide richer context during ADS creation
- Improve consistency without executing tests

---

### Splunk (Conceptual)

A Splunk MCP server could provide:
- Schema and field reference context
- Query structure guidance
- Read-only validation hints

This enables SPARK to:
- Assist analysts in drafting queries
- Reduce syntax errors
- Improve portability across environments

No searches would be executed automatically.

---

## Security and Risk Considerations

MCP integrations introduce additional trust boundaries.

Users should:
- Treat all external context as untrusted input
- Run MCP servers in controlled environments
- Review outputs before incorporation into SPARK artifacts

SPARK will not assume correctness or safety of MCP-provided data.

---

## Status

MCP integrations are **not required** and may be introduced incrementally.

This document describes **design intent**, not a delivery commitment.

Implementation details may evolve as MCP standards mature.
