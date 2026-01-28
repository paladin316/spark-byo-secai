# SPARK Chat-First Workspace Model

This document defines the **Chat-First Workspace** used in SPARK — a notebook-scoped, analyst-controlled environment designed to capture reasoning, exploration, and decision-making as part of the threat intelligence lifecycle.

This Workspace is not the SPARK platform as a whole.  
It is a **focused analytical surface** where analysts think, ask questions, draft queries, and record conclusions.

---
> This document describes the **Notebook-level Workspace UI**.
> For the broader SPARK Workspace model that governs artifact lifecycle and traceability, see `docs/architecture/workspace-platform.md`.

## What This Workspace Is

The SPARK Workspace is a **chat-first notebook** that combines:

- Conversational analysis
- Analyst notes
- Draft hunt logic and queries
- Optional AI augmentation
- Persistent, notebook-scoped memory

Each Workspace corresponds to a **single analytical effort**, such as:
- A threat hunt
- An investigation thread
- Detection research
- Intelligence analysis

---

## Notebook-Scoped Memory

Each Workspace notebook maintains its own **isolated memory context**.

This means:
- Context does not bleed between notebooks
- Prior chat history informs future responses *within the same notebook*
- Analysts can reason over time without restating assumptions

Notebook memory is:
- Explicit
- Persistent
- Analyst-owned

Deleting a notebook deletes its memory.

---

## Chat-First by Design

The Workspace is intentionally **chat-first**, not form-first.

Analysts use the Workspace to:
- Ask questions
- Explore hypotheses
- Reason through findings
- Draft detection ideas
- Capture narrative context that does not fit clean schemas

Chat is treated as **analysis**, not just interaction.

---

## Inline Notes and Query Blocks

Within the chat Workspace, analysts can create:

- Inline notes
- Draft hunt queries
- Pseudo-code or detection logic
- Observations tied to evidence

These blocks:
- Are not executed automatically
- Are not assumed to be correct
- Serve as working material

They can later be promoted into formal artifacts (Hunts, Findings, ADS).

---

## Optional AI Augmentation (Per Message)

AI assistance in the Workspace is **optional and scoped per interaction**.

AI assistance does not persist notebook memory independently of analyst interaction.

Key characteristics:
- AI can be enabled or disabled per message
- AI suggestions are grounded in notebook context
- AI output is advisory only

The Workspace does not allow AI to:
- Persist content without analyst action
- Modify artifacts automatically
- Execute queries or commands

This preserves analyst control at every step.

---

## Relationship to RAG

When enabled, the Workspace may use **Retrieval-Augmented Generation (RAG)**.

RAG context may include:
- Notebook chat history
- Analyst notes
- Linked artifacts (Intel Briefs, Hunts, Findings)
- Explicitly selected references

RAG is:
- Contextual
- Bounded
- Notebook-scoped

AI responses are derived from retrieved context — not global knowledge.

---

## Persistence and Continuity

Workspace notebooks persist across sessions.

This allows analysts to:
- Pause and resume work
- Return to prior reasoning
- Review how conclusions were reached
- Maintain continuity during long-running hunts

The Workspace acts as an **analytical journal**, not a transient UI.

---

## What the Workspace Is Not

This Workspace is **not**:

- An execution engine
- A case management system
- An alert triage console
- An autonomous agent
- A replacement for Hunt / Finding / ADS artifacts

It is a **thinking space**, not a control plane.

---

## Security and Trust Boundaries

From a security perspective:

- All input is treated as untrusted
- Chat content may include adversarial text
- AI suggestions are never authoritative
- No automatic execution occurs

Prompt injection signals may appear in Workspace content; these are informational and expected in DFIR workflows.

See `docs/architecture/security-model.md` for details.

---

## Why This Workspace Exists

Security analysis is rarely linear.

Analysts need space to:
- Explore ideas
- Make mistakes
- Revise assumptions
- Capture partial understanding

The SPARK Chat-First Workspace exists to **preserve analyst thinking**, not just final outputs.

---

## Summary

The SPARK Workspace is a **chat-first, notebook-scoped analytical environment** designed to:

- Capture reasoning as it happens
- Preserve context over time
- Support optional AI augmentation
- Enable promotion of ideas into formal artifacts

It is where **analysis lives before it becomes structure**.
