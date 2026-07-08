# TWPP Methodology

## Objective

The Threat Weaponization Prediction Program provides a repeatable methodology for determining whether a vulnerability is likely to become operationally relevant to attackers.

The methodology is designed to help security teams answer:

1. Is this vulnerability likely to be weaponized?
2. How quickly could weaponization occur?
3. Which customers, assets, or environments are exposed?
4. What hunts should be deployed now?
5. What detections are missing?
6. How do we measure whether the forecast was accurate?

## Core Operating Model

```text
Collect Intelligence
        ↓
Normalize Evidence
        ↓
Correlate Signals
        ↓
Forecast Weaponization
        ↓
Estimate Time-to-Exploitation
        ↓
Generate Threat Hunts
        ↓
Analyze Exposure
        ↓
Score Customer Risk
        ↓
Identify Detection Gaps
        ↓
Measure Outcomes
        ↓
Improve Model
```

## 1. Vulnerability Intelligence

This layer captures the vulnerability facts:

- CVE identifier
- affected product or platform
- vulnerability class
- CVSS score
- exploitation prerequisites
- attack vector
- privilege requirements
- patch availability
- public disclosure date
- exploit or proof-of-concept availability
- CISA KEV status
- vendor advisory status
- known exploitation status

## 2. Intelligence Correlation

TWPP correlates multiple signal types:

- vendor advisories
- CTI reporting
- exploit repositories
- vulnerability databases
- CISA KEV
- social media discussion
- GitHub activity
- Shodan / internet exposure
- threat actor reporting
- historical exploitation patterns

## 3. Weaponization Forecasting

The forecasting layer estimates whether attackers are likely to adopt the vulnerability into real-world operations.

Important forecast indicators include:

- public exploit availability
- exploit reliability
- attacker value
- ease of exploitation
- breadth of affected deployments
- internet exposure
- privilege escalation utility
- ransomware utility
- cloud or container relevance
- inclusion in exploit frameworks
- prior exploitation of similar vulnerability classes

## 4. Threat Hunt Generation

The threat hunt layer converts the forecast into operational action.

Each hunt should include:

- hunt hypothesis
- MITRE ATT&CK mapping
- required telemetry
- query language
- detection logic
- expected false positives
- investigation steps
- escalation guidance

## 5. Exposure Analysis

The exposure layer determines which environments are actually at risk.

Exposure analysis should evaluate:

- vulnerable software inventory
- internet-facing systems
- cloud assets
- container platforms
- business criticality
- identity exposure
- lateral movement paths
- compensating controls

## 6. Customer Risk Scoring

Customer risk scoring translates technical vulnerability data into operational prioritization.

Risk should include:

- likelihood of weaponization
- asset exposure
- business impact
- exploitability
- patch status
- control maturity
- detection coverage

## 7. Detection Gap Analysis

Detection gap analysis determines whether defenders can observe the behaviors likely to appear during exploitation.

This includes:

- telemetry availability
- current detection coverage
- missing log sources
- missing endpoint visibility
- missing identity visibility
- missing cloud telemetry
- missing container telemetry
- new detection opportunities

## 8. Outcome Metrics

TWPP must measure whether forecasts were useful.

Core metrics include:

- Mean Time to Weaponization (MTTW)
- Time-to-Exploitation (TTE)
- Mean Time to Hunt
- Mean Time to Detection
- Mean Time to Patch
- forecast accuracy
- precision / recall
- false positive rate
- analyst hours saved
- customer risk reduction

## Analyst Review Requirement

TWPP should never be treated as a fully automated decision system. Every forecast should be reviewed by an analyst before publication, customer notification, detection deployment, or executive reporting.
