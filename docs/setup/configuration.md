# SPARK Configuration & Setup

This document explains how to configure **SPARK (Powered by BYO-SECAI)**, including application settings, proxy and TLS behavior, web fetching, and Retrieval-Augmented Generation (RAG).

SPARK is designed to be **local-first, analyst-driven, and transparent**. All configuration options are explicit and user-controlled—there are no hidden outbound calls or implicit data sharing.

---

## Configuration Model

SPARK is configured via a single configuration file:

```

config.yaml

````

### Configuration precedence

Settings are applied in the following order (highest to lowest priority):

1. Environment variables (where supported)
2. `config.yaml`
3. Application defaults

This allows safe defaults while still enabling environment-specific overrides.

---

## Safety & Trust Model (Read This First)

SPARK intentionally separates **exploration** from **production artifacts**.

- **Notebook Workspace**
  - Used for exploration, enrichment, and recall
  - RAG and web search operate here
  - No automatic promotion to production artifacts

- **Platform Workspace**
  - System of record for Intel Briefs, Hunt Packages, Findings, and ADS
  - Enforced validation contracts
  - Explicit analyst approval required

**RAG and web content never bypass Platform Workspace approvals.**

---

## Web Search vs Web Ingestion (Important Distinction)

SPARK supports two distinct web capabilities:

### 1. Web search (metadata / discovery)
- Query search engines for context
- No page content is ingested
- Safe default behavior

### 2. Web ingestion (page fetch + content use)
- Fetches and parses page content
- Content may be added to context or reports
- Explicitly opt-in

These behaviors are controlled separately.

---

## Web Configuration

```yaml
web_enabled: true
web_enabled_by_default: false
web_fetch_pages: false
web_provider: duckduckgo
web_max_results: 5
web_timeout_s: 15
web_cache_ttl_s: 1800
fetch_source_urls: true
max_source_chars: 6000
````

### Capability vs Default Behavior

- `web_enabled`
    
    - Enables web functionality in SPARK
        
    - If `false`, all web features are disabled
        
- `web_enabled_by_default`
    
    - Controls whether web is **on by default** in the UI or workflows
        
    - Recommended default: `false` (local-first)
        

### Enabling web ingestion

To allow SPARK to fetch and ingest page content:

```yaml
web_fetch_pages: true
```

Without this, SPARK may still search but will not ingest page text.

---

## RAG (Retrieval-Augmented Generation)

RAG enhances analysis by retrieving relevant local context during Notebook Workspace exploration.

```yaml
rag_enabled: true
rag_top_k: 6
rag_chunk_chars: 1200
rag_overlap_chars: 200
data_dir: data
```

### What RAG is used for

- Recall of previously ingested documents
    
- Analyst-side exploration and synthesis
    
- Supporting narrative and technical context
    

### What RAG is **not** used for

- Automatic artifact generation
    
- Approval bypass
    
- Silent enrichment of Platform Workspace artifacts
    

### Tuning guidance

- Increase `rag_top_k` if responses feel thin
    
- Reduce `rag_chunk_chars` if retrieval feels off-topic
    
- Smaller chunks often work better for highly technical documents
    

### Local storage note

All RAG data is stored locally under:

```
data_dir: data
```

**Recommendation:** add this directory to `.gitignore`.

---

## Proxy Configuration

SPARK supports explicit proxy configuration for all outbound HTTP/S traffic.

```yaml
network:
  proxy:
    enabled: false
    mode: explicit
    http: http://127.0.0.1:3128
    https: http://127.0.0.1:3128
    no_proxy: ''
    username: ''
    password: ''
```

### Enabling a proxy

```yaml
network:
  proxy:
    enabled: true
    http: http://proxy.local:3128
    https: http://proxy.local:3128
    no_proxy: 'localhost,127.0.0.1,.internal.company.com'
```

### Proxy authentication

```yaml
network:
  proxy:
    username: 'USERNAME'
    password: 'PASSWORD'
```

---

## TLS & Certificate Handling

```yaml
network:
  tls:
    verify: true
    ca_bundle_path: ''
```

### Enterprise TLS inspection (recommended approach)

If your organization uses TLS interception:

```yaml
network:
  tls:
    verify: true
    ca_bundle_path: '/path/to/corporate-ca-bundle.pem'
```

### Troubleshooting only (not recommended for production)

```yaml
network:
  tls:
    verify: false
```

Disable verification **only temporarily** to diagnose certificate issues.

---

## Configuration Philosophy

- All outbound behavior is visible and configurable
    
- Local-first defaults are intentional
    
- Exploration and production are explicitly separated
    
- Analysts remain in control at every stage
    

For detailed descriptions of every configuration key, see:

```
docs/setup/settings-reference.md
```

For focused setup guides, see:

- `docs/setup/rag.md`
    
- `docs/setup/proxy.md`
    
