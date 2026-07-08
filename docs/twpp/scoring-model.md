# TWPP Scoring Model

## Purpose

The scoring model is intended to produce consistent, explainable prioritization. It is not a substitute for analyst judgment.

TWPP scoring should be transparent enough that an analyst can explain why a vulnerability received a high or low forecast.

## Primary Scores

| Score | Description |
|---|---|
| Weaponization Forecast Score (WFS) | Likelihood that the vulnerability will be adopted into attacker tradecraft. |
| Time-to-Exploitation (TTE) | Estimated time window before observed or likely exploitation. |
| Exposure Score | Degree to which customer environments are vulnerable or reachable. |
| Detection Gap Score | Degree to which existing telemetry and detections are insufficient. |
| Customer Risk Score | Combined business and technical prioritization score. |

## Weaponization Forecast Score

The WFS should be calculated from weighted indicators.

| Indicator | Example Weight | Description |
|---|---:|---|
| Public exploit availability | High | Public PoC, exploit module, or weaponized code exists. |
| Exploit reliability | High | Exploit succeeds consistently across target environments. |
| Exploit simplicity | High | Low complexity, limited prerequisites, or easy reproduction. |
| Attacker utility | High | Supports privilege escalation, RCE, credential access, persistence, or defense evasion. |
| Exposure prevalence | High | Commonly deployed product, cloud service, endpoint agent, or infrastructure component. |
| Internet exposure | High | Attack surface is externally reachable. |
| Threat actor interest | Medium / High | Mentioned by ransomware, APT, exploit broker, or criminal communities. |
| CISA KEV status | High | Known exploited vulnerability. |
| Patch availability | Medium | Patch exists, but exploitation risk remains during patch window. |
| Historical pattern match | Medium | Similar vulnerabilities were rapidly exploited in the past. |

## Suggested WFS Bands

| Score | Rating | Interpretation |
|---:|---|---|
| 0-24 | Low | Limited attacker utility or insufficient evidence. |
| 25-49 | Moderate | Some exploitation indicators exist, but adoption is uncertain. |
| 50-74 | High | Multiple weaponization indicators present. Hunt and patch prioritization recommended. |
| 75-100 | Critical | Strong likelihood of near-term exploitation or confirmed active exploitation. Immediate action recommended. |

## Time-to-Exploitation Estimate

TTE should be expressed as a range, not a single value.

| TTE Band | Interpretation |
|---|---|
| 0-72 hours | Exploitation is active, trivial, or already weaponized. |
| 3-7 days | Public exploit exists and target population is high value. |
| 7-21 days | Strong adoption indicators, but no confirmed widespread exploitation. |
| 21-60 days | Plausible attacker adoption, but barriers remain. |
| 60+ days | Weaponization unlikely or requires specialized conditions. |

## Customer Risk Score

Customer risk should combine vulnerability likelihood with exposure and business context.

| Component | Description |
|---|---|
| Weaponization likelihood | Derived from WFS. |
| Asset exposure | Whether affected systems exist in the customer environment. |
| Business criticality | Importance of affected systems. |
| Patch status | Whether patches or mitigations are deployed. |
| Detection coverage | Whether exploitation or post-exploitation behaviors are observable. |
| Compensating controls | EDR, isolation, identity controls, segmentation, WAF, cloud controls. |

## Detection Gap Score

| Score | Meaning |
|---:|---|
| 0-25 | Good coverage exists. |
| 26-50 | Some coverage exists, but meaningful gaps remain. |
| 51-75 | Major telemetry or detection limitations exist. |
| 76-100 | Exploitation is likely difficult to observe with current controls. |

## Notes

This scoring model is intentionally conceptual. Production scoring should use version-controlled weights, analyst review, validation data, and post-outcome calibration.
