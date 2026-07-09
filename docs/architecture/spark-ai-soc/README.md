# SPARK AI SOC — Phase 0 Design

SPARK AI SOC is a plug-and-play AI-assisted security operations module for the SPARK project. Phase 0 is designed to use external AI APIs today while keeping the architecture provider-agnostic and local-first ready.

## Phase 0 Goal

Build an AI-enabled SOC proof of concept that supports four analyst roles:

```text
Threat Intel Analyst
Threat Hunter
Detection Engineer
Incident Responder
```

Each role is implemented as an AI-assisted agent with defined inputs, outputs, prompts, guardrails, evidence handling, and schema-enforced artifacts.

## Design Decision

```text
API-first execution
Local-first architecture
Provider-agnostic agents
Markdown-first artifacts
Schema-enforced outputs
SPARK-compatible folder structure
```

## Architecture

```text
                    ┌──────────────────────────┐
                    │        SPARK UI / CLI     │
                    └─────────────┬────────────┘
                                  │
                    ┌─────────────▼────────────┐
                    │     Orchestration Layer   │
                    │  Agent Router / Workflow  │
                    └─────────────┬────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
┌───────▼────────┐       ┌────────▼────────┐       ┌────────▼────────┐
│ Intel Analyst  │       │ Threat Hunter   │       │ Detection Eng   │
│ Agent          │       │ Agent           │       │ Agent           │
└───────┬────────┘       └────────┬────────┘       └────────┬────────┘
        │                         │                         │
        └──────────────┬──────────┴──────────────┬──────────┘
                       │                         │
              ┌────────▼────────┐       ┌────────▼────────┐
              │ Incident        │       │ Evidence /      │
              │ Responder Agent │       │ Memory Store    │
              └────────┬────────┘       └────────┬────────┘
                       │                         │
              ┌────────▼─────────────────────────▼────────┐
              │        SPARK Output Generators             │
              │ TWPP / Hunt Package / ADS / IR Report      │
              └────────────────────────────────────────────┘
```

## Recommended Runtime Profile

For Phase 0 on a 32 GB RAM Intel Platform:

```text
Primary AI: External API
Local AI: Optional fallback
Local storage: Evidence, schemas, prompts, outputs
Local compute: Orchestration, validation, parsing, report generation
```

## Example Commands

```bash
spark-ai-soc analyze-cve CVE-2026-43499 --workflow cve_to_twpp
spark-ai-soc analyze-poc ./data/samples/ghostlock/ --workflow poc_to_attack_paths
spark-ai-soc create-hunt ./data/normalized/ghostlock.json --platform crowdstrike
spark-ai-soc create-ads ./spark_ai_soc/output/hunts/ghostlock_hunt.md
```

## Build Milestones

1. **Skeleton** — project structure, configs, AI Gateway interface, provider abstraction.
2. **Agent Profiles** — role-based agents and reusable prompts.
3. **Workflow Engine** — CVE, PoC, intel, hunt, detection, and IR workflows.
4. **Output Contracts** — JSON schemas, Markdown output, evidence storage.
5. **SPARK Integration** — TWPP, hunt package, ADS, and IR report compatibility.

## Status

This package is a Phase 0 scaffold. Provider implementations are intentionally thin so the module can support OpenAI, Anthropic, Gemini, Ollama, LM Studio, or future internal models without changing agent logic.
