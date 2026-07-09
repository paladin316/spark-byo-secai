# SPARK AI SOC Architecture

## Core Principle

Agents do not call AI providers directly. Every agent sends requests through the AI Gateway. The gateway determines whether the request is routed to OpenAI, Anthropic, Gemini, Ollama, LM Studio, or a future internal model.

## Main Components

| Component | Responsibility |
|---|---|
| SPARK UI / CLI | Receives analyst requests and launches workflows. |
| Orchestration Layer | Routes tasks, calls agents, passes context, saves evidence, and produces artifacts. |
| AI Gateway | Provides a common completion interface across external and local models. |
| Agent Layer | Executes role-specific analysis for intel, hunting, detection, and IR. |
| Evidence Store | Preserves source material, normalized context, prompts, and generated outputs. |
| Output Generators | Creates TWPP assessments, hunt packages, ADS drafts, and IR reports. |

## Supported Workflows

```text
CVE → TWPP Assessment
PoC Code → Attack Path Simulation
Threat Intel → Hunt Package
Hunt Results → IR Report
Detection Gap → ADS Draft
```

## Local-First Readiness

Phase 0 may use external AI APIs for speed, but the design keeps model providers behind a gateway abstraction. This prevents SPARK from becoming dependent on any single provider.
