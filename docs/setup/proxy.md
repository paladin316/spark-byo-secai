# Proxy & TLS Configuration

This document explains how **SPARK (Powered by BYO-SECAI)** handles outbound network traffic, including HTTP/S proxy configuration and TLS certificate handling.

SPARK makes **no hidden outbound calls**. All external network behavior is explicit, configurable, and visible to the analyst.

---

## When Proxy Configuration Is Needed

You may need to configure a proxy if:

- Your environment restricts direct outbound internet access
- You operate behind a corporate HTTP/S proxy
- TLS interception is performed by enterprise security tooling
- Web search or URL fetch operations fail without a proxy

If your environment allows direct outbound traffic, **no proxy configuration is required**.

---

## Default Proxy Configuration

By default, proxy support is present but disabled:

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
````

When `enabled: false`, SPARK does not route traffic through a proxy.

---

## Enabling an Explicit Proxy

To enable proxy routing for outbound HTTP and HTTPS traffic:

```yaml
network:
  proxy:
    enabled: true
    mode: explicit
    http: http://proxy.local:3128
    https: http://proxy.local:3128
    no_proxy: 'localhost,127.0.0.1,.internal.company.com'
```

### `no_proxy`

Use `no_proxy` to bypass the proxy for:

- Localhost traffic
    
- Internal domains
    
- Private infrastructure endpoints
    

This helps prevent unnecessary routing and authentication issues.

---

## Proxy Authentication

If your proxy requires authentication:

```yaml
network:
  proxy:
    enabled: true
    username: 'USERNAME'
    password: 'PASSWORD'
```

Credentials are only used for outbound proxy authentication and are not stored elsewhere.

---

## TLS & Certificate Handling

SPARK validates TLS certificates by default.

```yaml
network:
  tls:
    verify: true
    ca_bundle_path: ''
```

---

## Enterprise TLS Interception (Recommended Configuration)

If your organization performs TLS inspection, configure a trusted CA bundle instead of disabling verification:

```yaml
network:
  tls:
    verify: true
    ca_bundle_path: '/path/to/corporate-ca-bundle.pem'
```

This allows SPARK to:

- Maintain certificate verification
    
- Work cleanly behind enterprise security controls
    
- Avoid unsafe TLS bypasses
    

---

## Troubleshooting Only: Disabling TLS Verification

```yaml
network:
  tls:
    verify: false
```

⚠️ **Use this setting only for temporary troubleshooting.**

Disabling TLS verification reduces security guarantees and should not be used in production or long-term environments.

---

## Proxy Configuration & the SPARK Trust Model

Proxy behavior in SPARK follows the same principles as the rest of the platform:

- Explicit configuration
    
- No implicit network access
    
- Analyst-visible behavior
    
- Safe defaults
    

SPARK will never silently bypass proxy or TLS settings.

For related configuration topics, see:

- `docs/setup/configuration.md`
    
- `docs/setup/settings-reference.md`
    
