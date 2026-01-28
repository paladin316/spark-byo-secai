# Threat Hunt Package – {{THREAT_NAME}}

### *{{HUNT_TAGLINE_OR_FOCUS}}*  
<!-- Example: "Endpoint Telemetry–Focused Hunt Using CrowdStrike Falcon" -->

---

## 1. Threat Overview

Provide a concise narrative that explains:

- **What the threat is:** {{THREAT_FAMILY_OR_CAMPAIGN}}
- **How it operates:** {{KEY_BEHAVIORS_AND_TACTICS}}
- **Why it matters to your org:** {{BUSINESS_IMPACT_SUMMARY}}
- **Key capabilities:**
  - {{CAPABILITY_1}}  
  - {{CAPABILITY_2}}  
  - {{CAPABILITY_3}}

You can also briefly mention relevant ATT&CK techniques (e.g., T1059, T1552, etc.).

---

## 2. Objective

Describe what this hunt is trying to prove or disprove.

- **Primary Objective:** {{PRIMARY_OBJECTIVE}}
- **Secondary Objectives (optional):**
  - {{SECONDARY_OBJECTIVE_1}}
  - {{SECONDARY_OBJECTIVE_2}}

Example framing:  
> Determine whether {{ORG_NAME}} endpoints show evidence of {{THREAT_NAME}} activity, such as {{KEY_BEHAVIOR_1}}, {{KEY_BEHAVIOR_2}}, or {{KEY_BEHAVIOR_3}}.

---

## 3. Hunt Scope

### 3.1 In-Scope

Define what data sources and systems are in-scope:

- **Data Sources / Telemetry**
  - {{DATA_SOURCE_1}} (e.g., ProcessRollup2)
  - {{DATA_SOURCE_2}} (e.g., ScriptControlScanInfo)
  - {{DATA_SOURCE_3}}
- **System Types**
  - {{SYSTEM_TYPE_1}} (e.g., Developer endpoints)
  - {{SYSTEM_TYPE_2}} (e.g., Build-support servers)
  - {{SYSTEM_TYPE_3}}
- **Operating Systems**
  - {{OS_1}} (e.g., Windows)
  - {{OS_2}} (e.g., macOS)
  - {{OS_3}} (e.g., Linux)

### 3.2 Out-of-Scope

Call out anything explicitly out-of-scope so stakeholders understand boundaries:

- {{OUT_OF_SCOPE_ITEM_1}} (e.g., CI/CD pipeline instrumentation)
- {{OUT_OF_SCOPE_ITEM_2}}
- {{OUT_OF_SCOPE_ITEM_3}}

---

## 4. High-Fidelity Indicators & Hunt Queries

> **Note:** Repeat the subsection pattern below (4.1, 4.2, 4.3, …) for each analytic you are running.  
> Use one subsection per distinct *detection idea* or *behavioral pattern*.

---

### 4.1 {{DETECTION_FOCUS_1_TITLE}}
<!-- Example: "Execution of Malicious Installer / Config Script" -->

**Purpose**

Describe what this analytic is trying to catch, in one or two sentences:

> {{DETECTION_FOCUS_1_PURPOSE}}

**Query Logic (CQL / SPL / KQL / Other)**

```cql
{{DETECTION_FOCUS_1_QUERY}}
```

**Notes / Tuning Guidance**

- {{DETECTION_FOCUS_1_NOTE_1}}
- {{DETECTION_FOCUS_1_NOTE_2}}

---

### 4.2 {{DETECTION_FOCUS_2_TITLE}}
<!-- Example: "Credential Harvesting Behavior" -->

**Purpose**

> {{DETECTION_FOCUS_2_PURPOSE}}

**Query Logic**

```cql
{{DETECTION_FOCUS_2_QUERY}}
```

**Notes / Tuning Guidance**

- {{DETECTION_FOCUS_2_NOTE_1}}
- {{DETECTION_FOCUS_2_NOTE_2}}

---

### 4.3 {{DETECTION_FOCUS_3_TITLE}}
<!-- Add more subsections (4.4, 4.5, etc.) as needed -->

**Purpose**

> {{DETECTION_FOCUS_3_PURPOSE}}

**Query Logic**

```cql
{{DETECTION_FOCUS_3_QUERY}}
```

**Notes / Tuning Guidance**

- {{DETECTION_FOCUS_3_NOTE_1}}
- {{DETECTION_FOCUS_3_NOTE_2}}

---

## 5. Findings

Summarize the outcome of running all queries and analytics.
{{This section to be completed upon completion of the Threat Hunt.}}

### 5.1 Summary

Provide a clear, non-technical summary first:
{{This section to be completed upon completion of the Threat Hunt.}}
> {{FINDINGS_PLAIN_LANGUAGE_SUMMARY}}

### 5.2 Technical Findings

Use bullets for clarity:
{{This section to be completed upon completion of the Threat Hunt.}}
- {{FINDING_ITEM_1}}  
- {{FINDING_ITEM_2}}  
- {{FINDING_ITEM_3}}  

Include whether any **Indicators of Compromise (IOCs)** or **suspicious behaviors** were found:

- **IOC/Behavior Presence:** {{NONE_FOUND | FOUND_AND_LISTED_BELOW}}

If anything was found, describe:

- **Affected Hosts / Users:** {{AFFECTED_ASSETS_SUMMARY}}
- **Earliest Known Activity:** {{EARLIEST_ACTIVITY_TIMESTAMP}}
- **Latest Known Activity:** {{LATEST_ACTIVITY_TIMESTAMP}}

---

## 6. Recommended Analyst Interpretation

Give the reader a way to interpret the hunt results.
{{This section to be completed upon completion of the Threat Hunt.}}
> Based on the current hunt results, we assess that:
> - {{INTERPRETATION_STATEMENT_1}}  
> - {{INTERPRETATION_STATEMENT_2}}  

Clarify what level of confidence the team has:

- **Overall Assessment:** {{NO_ACTIVITY_DETECTED | LIMITED_ACTIVITY | CONFIRMED_ACTIVITY}}
- **Confidence Level:** {{LOW | MEDIUM | HIGH}}  
- **Reasoning:** {{INTERPRETATION_REASONING}}

---

## 7. Reporting Summary (Copy/Paste Ready)

This section should be easy to drop into an email, ticket, or slide.

**Threat:** {{THREAT_NAME}}  
**Status:** {{STATUS_SUMMARY}}  
**Confidence:** {{LOW | MEDIUM | HIGH}}  
**Detection Coverage:** {{COVERAGE_STATEMENT}}  
**Scope:** {{SCOPE_SUMMARY}}  

**Key Points:**

1. {{KEY_POINT_1}}
2. {{KEY_POINT_2}}
3. {{KEY_POINT_3}}

**Recommended Next Steps:**

- {{NEXT_STEP_1}}
- {{NEXT_STEP_2}}
- {{NEXT_STEP_3}}

---

## 8. Optional Add-Ons (If Applicable)

List any additional artifacts you created or plan to create for this hunt:

- {{ADDON_1}} (e.g., Intel Briefing Report)
- {{ADDON_2}} (e.g., Executive Summary Slide)
- {{ADDON_3}} (e.g., Atomic Red Team scenario for validation)
- {{ADDON_4}} (e.g., JSON / CSV export of hunt results)

---

## 9. Hunt Metadata

Capture metadata so you can add this package into your Threat Hunt Library.

- **Hunt ID:** {{HUNT_ID}}  
- **Owner / Primary Hunter:** {{OWNER_NAME}}  
- **Date Range Searched:** {{DATE_RANGE}}  
- **Data Sources Used:** {{DATA_SOURCES_LIST}}  
- **Related Tickets (Jira / ServiceNow, etc.):** {{RELATED_TICKETS}}  
- **Related Intel Brief ID:** {{INTEL_BRIEF_ID}}  
- **Related ADS ID(s):** {{ADS_IDS}}  

---

*Template version:* {{TEMPLATE_VERSION}}  
*Last updated:* {{LAST_UPDATED_DATE}}  
