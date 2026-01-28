# Threat Intelligence Brief Report Template

## Title
Definition: A concise, descriptive headline summarizing the main threat or issue.
Description: Clearly states the 'what' and 'why' of the report in 8–12 words. Avoid jargon and ambiguity.
Notes:
- Example: “Emerging Ransomware Campaign Targets Healthcare Cloud Infrastructure”
- Avoid vague titles like “Cyber Threat Report.”

## Date / Author / Reference ID
Definition: Metadata that supports report traceability and attribution.
Description: Lists the report date, author or analytic team, and reference number (e.g., CSDEV-####).
Notes:
- Include classification or distribution level (e.g., Internal Use Only).
- Helps in audit and revision tracking.

## BLUF (Bottom Line Up Front)
Definition: A succinct summary of the analytic judgment or key takeaway.
Description: Present the main conclusion and its significance in the first paragraph.
Structure:
- What: What’s happening or what was discovered
- Why now: Why this is relevant or time-sensitive
- So what: Why it matters to the organization
- Impact so far: Evidence of exploitation, activity, or consequences
- What next / Outlook: Forecast or expected developments
Notes:
- Keep to 3–5 sentences maximum.
- Avoid background context here — only key judgments.
- Example: “We assess with moderate confidence that the new BRICKSTORM malware family is leveraging compromised Citrix infrastructure for data exfiltration across U.S. healthcare organizations.”

## Background
Definition: Provides context to understand the issue’s origin and scope.
Description: Summarizes relevant historical data, related incidents, or campaign evolution.
Notes:
- Keep factual and chronological.
- Example: Describe when and where the threat emerged, prior observed activity, and known actors.

## Threat Description
Definition: Detailed overview of the threat actor, campaign, or vulnerability.
Description: Explains how the threat operates — its tools, techniques, and procedures (TTPs).
Notes:
- Include MITRE ATT&CK mapping where possible.
- Example: T1566.002 – Spearphishing Link, C2 on .ru domains, BRICKSTORM Loader variant.

## Current Assessment
Definition: Analyst judgment on what is happening and what it means.
Description: Presents analytic conclusions supported by evidence and logic.
Notes:
- Use words of estimative probability (likely, probably, almost certainly).
- Example: “It is likely this activity is linked to STORM-0501 ransomware cluster given overlapping C2 patterns and payload hashes.”

## Evidence and Indicators
Definition: Observable data supporting the analysis.
Description: Lists key IOCs, filenames, IPs, hashes, domains, and TTPs observed.
Notes:
- Organize by type: network, host, cloud, identity.
- Include confidence ratings for each indicator.

## Impact Assessment
Definition: Evaluates the operational, financial, and reputational consequences.
Description: Connects technical findings to potential business effects.
Notes:
- Example: “If exploited, this vulnerability could allow lateral movement from Citrix Gateway to internal assets, impacting authentication and data integrity.”

## Confidence and Credibility Ratings
Definition: Quantitative or qualitative assessment of information reliability.
Description:
- Credibility: A–F (quality of source data)
- Reliability: 1–6 (source consistency or trustworthiness)
- Confidence: High / Medium / Low (analytic confidence)
Notes:
- Example: “We assess with moderate confidence (B2) that the actor is financially motivated.”
- Avoid overstatement; explain if confidence is low.

## Gaps and Collection Requirements
Definition: Identifies missing intelligence that limits analytic certainty.
Description: Summarizes what is not known and recommends collection tasks.
Notes:
- Avoid listing 'lack of time' or 'resources' as a gap.
- Example: “No telemetry confirming payload execution on internal endpoints.”

## Alternative Analysis
Definition: Considers other plausible explanations or hypotheses.
Description: Evaluates secondary scenarios and discusses their likelihood.
Notes:
- Example: “Alternative Hypothesis: This activity may stem from an uncoordinated red team exercise rather than a real intrusion.”

## Outlook / Future Implications
Definition: Forecast of how the threat is expected to evolve.
Description: Discusses potential next moves, risk trajectory, or broader implications.
Notes:
- Example: “Future variants may expand to hybrid cloud environments via compromised service accounts.”

## Recommended Actions
Definition: Practical defensive, monitoring, and response measures.
Description:
- Supervisory Actions: Required response or escalation.
- Recommendations & Opportunities: Suggested mitigations or detection improvements.
Notes:
- Example: Implement CrowdStrike IOC blocking for BRICKSTORM hashes.

## Summary Paragraph(s)
Definition: Cohesive synthesis of findings and significance.
Description: Each paragraph focuses on one key point (topic sentence → evidence → analysis).
Notes:
- Follow structure: Topic sentence → Explanation → Example(s) → So what?

## Appendix
Definition: Supporting material not critical to the main narrative.
Description: May include detailed IOCs, diagrams, or MITRE mappings.
Notes:
- Include confidence terms chart (Sherman Kent scale).

