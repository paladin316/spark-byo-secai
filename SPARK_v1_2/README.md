SPARK v1.2 — Application Runtime

Purpose

SPARK_v1_2/ represents the execution layer of SPARK.

It is responsible for:

Running the SPARK application

Managing local analyst configuration and state

Enabling structured workflows across:

Threat Intelligence

Threat Hunting

Detection Strategy authoring



All outputs produced here are designed to align with SPARK’s core principles: preserve intent, enforce validation, and maintain auditability.


---

Scope Boundaries

This directory does not define:

The philosophy behind SPARK

The analytical lifecycle model

Template intent or governance

Architecture or design rationale


Those concepts are intentionally documented elsewhere to keep runtime concerns clean and focused.


---

Project Orientation

To understand SPARK as a platform, start with:

Project Overview: /README.md

Concepts & Architecture: /docs/

Templates & Lifecycle Examples: /docs/templates/, /docs/demo/


This directory exists to run SPARK, not to explain it.


---

Design Intent

SPARK is:

Analyst-first

Local-first

Explainable and auditable

AI-augmented, not AI-driven


Analyst review and approval are required before artifacts advance between stages.


---

> This directory executes SPARK.
The meaning of SPARK lives in the documentation.
