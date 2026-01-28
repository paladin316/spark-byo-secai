# Settings Reference

This document provides a reference for all configurable settings in
**SPARK (Powered by BYO-SECAI)**.

Most users do **not** need to change every setting. Defaults are chosen
to be safe, local-first, and analyst-driven.

Use this document to understand what settings exist and when it is
appropriate to modify them.

---

## Guidance on Modifying Settings

Many settings in SPARK control governance, validation, and safety
behavior. Changing them may alter trust assumptions or weaken guardrails.

If you are unsure about a setting, leave it at its default value.

---

## Settings reference (your config keys, grouped)

### Contracts & enforcement

These settings define SPARK’s governance model. Most users should not
change these unless developing or testing new contracts.

- `contract_enforcement_mode: strict`
- `contract_regen_attempts: 2`
- `intel_brief_contract_profile: intel_brief_v1_2`
- `hunt_package_contract_profile: threat_hunt_v1_0`

---

### Approval autocorrect gates

These settings control how SPARK attempts to recover from contract
violations. Modifying them may weaken validation guarantees.

- `approval_autocorrect_enabled: true`
- `approval_autocorrect_max_attempts: 2`
- `approval_fail_open_after_autocorrect: true`
- `approval_autocorrect_prompt_pack: autocorrect`

---

### Hunt generation + autocorrect

Controls how threat hunt queries are generated, validated, and repaired.

- `hunt_glue_enabled: true`
- `hunt_glue_prompt_pack: hunt_v1`
- `hunt_autocorrect_enabled: true`
- `hunt_autocorrect_max_attempts: 2`
- `hunt_fail_open_after_autocorrect: true`
- `hunt_autocorrect_prompt_pack: hunt_v1`
- `hunt_min_queries: 2`
- `hunt_max_queries: 7`
- `query_language: CQL`

---

### RAG

Controls Retrieval-Augmented Generation used during Notebook Workspace
exploration.

- `rag_enabled: true`
- `rag_top_k: 6`
- `rag_chunk_chars: 1200`
- `rag_overlap_chars: 200`
- `data_dir: data`

---

### Web / fetch

Controls web search and optional content ingestion.

Web search and ingestion apply only to **Notebook Workspace**
exploration and do **not** automatically populate Platform Workspace
artifacts.

- `web_enabled: true`
- `web_enabled_by_default: false`
- `web_provider: duckduckgo`
- `web_max_results: 5`
- `web_timeout_s: 15`
- `web_fetch_pages: false`
- `web_cache_ttl_s: 1800`
- `web_enable_third_party_fetch_fallback: false`
- `web_enable_js_rendered_page_ingestion: false`
- `fetch_source_urls: true`
- `max_source_chars: 6000`

---

### Network

Controls outbound network behavior.

- `network.proxy.*` (explicit proxy, no_proxy, optional authentication)
- `network.tls.verify`
- `network.tls.ca_bundle_path`

---

### LLM (Ollama)

Controls the local LLM backend used by SPARK.

- `ollama_host: http://localhost:11434`
- `ollama_model: llama3.1`
- `ollama_temperature: 0.2`
- `ollama_request_timeout_s: 220`
- `local_ollama_models: [llama3:latest, mistral:latest, phi:latest]`

---

### Plugins

Optional enrichment and analysis integrations.

- `plugins.virustotal: true`
- `plugins.abuseipdb: true`
- `plugins.urlscan: false`
- `plugins.yara_scanner: false`
- `plugins.intel_fetcher: false`

---

### Grounding (CQL)

Controls grounding behavior for CrowdStrike LogScale (CQL) query generation.

- `cql_grounding_enabled: true`
- `cql_grounding_top_k_dictionary: 5`
- `cql_grounding_top_k_examples: 5`
- `cql_grounding_debug: true`

---

### App + safety

Application-level safety and transparency controls.

- `prod_safe_mode: true`
- `allow_dangerous_actions: false`
- `show_llm_errors: true`
- `render_cache_enabled: false`
- UI labels: `app_title`, `app_subtitle`, `report_footer`, `phase_label`
