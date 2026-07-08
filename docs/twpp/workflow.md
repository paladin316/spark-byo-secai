# TWPP Workflow

## End-to-End Lifecycle

```text
1. Monitor Intelligence Sources
2. Review New Vulnerabilities
3. Normalize Evidence
4. Score Weaponization Likelihood
5. Estimate Time-to-Exploitation
6. Generate Threat Hunts
7. Analyze Exposure
8. Score Customer Risk
9. Identify Detection Gaps
10. Recommend Actions
11. Measure Outcomes
12. Improve Forecasting Logic
```

## Phase 1: Monitor Intelligence Sources

Collect intelligence from:

- vendor advisories
- CISA KEV
- NVD / CVE feeds
- exploit repositories
- CTI reports
- security blogs
- GitHub
- social media
- Shodan / internet exposure
- EDR telemetry
- customer asset inventory

## Phase 2: Normalize Evidence

Convert raw intelligence into a normalized record.

Example normalized fields:

```yaml
cve_id: CVE-YYYY-NNNNN
name: Vulnerability Name
vendor: Vendor / Project
product: Product / Platform
vulnerability_class: RCE / LPE / Auth Bypass / Info Disclosure
cvss: 0.0
attack_vector: Network / Adjacent / Local / Physical
privileges_required: None / Low / High
user_interaction: None / Required
patch_available: true
public_exploit: true
known_exploitation: false
kev_status: false
```

## Phase 3: Correlate Evidence

Evidence should be correlated across technical, operational, and business dimensions.

Questions to answer:

- Is exploit code public?
- Is exploitation reliable?
- Does it enable initial access, privilege escalation, or lateral movement?
- Is the affected technology common in customer environments?
- Are threat actors discussing it?
- Does exploitation require authentication?
- Are patches available?
- Are customers exposed?

## Phase 4: Forecast Weaponization

Generate a Weaponization Forecast Score and TTE estimate.

Output should include:

- score
- confidence
- evidence summary
- reasoning
- missing evidence
- recommended review date

## Phase 5: Generate Threat Hunts

Create hunts based on likely attacker behavior.

Hunts should be organized by:

- initial access
- exploitation
- privilege escalation
- persistence
- defense evasion
- discovery
- credential access
- lateral movement
- exfiltration

## Phase 6: Analyze Exposure

Map vulnerability risk to actual customer environments.

Exposure sources:

- CMDB
- EDR inventory
- vulnerability scanner
- cloud asset inventory
- Kubernetes inventory
- internet exposure data
- identity and access data

## Phase 7: Identify Detection Gaps

Evaluate whether current controls can detect exploitation or post-exploitation.

Coverage review:

- endpoint telemetry
- identity telemetry
- network telemetry
- cloud telemetry
- container telemetry
- application logs
- kernel / audit telemetry

## Phase 8: Recommend Actions

Recommendations should be tailored by audience.

### Executive

- business risk
- patch urgency
- expected attacker adoption
- customer impact

### SOC

- monitoring guidance
- triage steps
- escalation criteria

### Threat Hunting

- hypotheses
- queries
- expected telemetry
- validation approach

### Detection Engineering

- detection opportunities
- telemetry gaps
- rule logic
- testing plan

### Vulnerability Management

- patch prioritization
- compensating controls
- verification steps

## Phase 9: Measure Outcomes

Outcome measurement closes the loop.

Track:

- Was exploitation observed?
- Did the forecast time window hold?
- Did hunts return true positives?
- Did detections fire?
- Were patches deployed before exploitation?
- How much analyst time was saved?
- What should be tuned in the model?
