# Behavior Intelligence Layer (v1) – Extraction Rules (Pseudo-code)

## Inputs
- intel_title: string
- intel_text: string (concatenated narrative sections)
- iocs: dict[str, list[str]] (normalized/deduped IOC bundles)
- sources: list[str]

## Output
- behaviors: list[Behavior]

## Vocabulary
- VERB_PATTERNS: list[(behavior_type, regex)]
- TOOL_BEHAVIORS: dict[tool_keyword -> {behavior_type, tactic}]
- SEQUENCE_HINTS: list[regex]

## Algorithm
1. Normalize IOCs (lowercase domains, strip trailing punctuation from URLs, dedupe).
2. Split intel_text into sentences (cheap split on punctuation).
3. For each sentence in order:
   a. Lowercase sentence.
   b. TOOL pass:
      - For each tool_keyword in TOOL_BEHAVIORS:
        - if tool_keyword appears:
          - anchors = pick_anchors(sentence, normalized_iocs)
          - emit Behavior(
              behavior_type=TOOL_BEHAVIORS[tool].behavior_type,
              tactic=TOOL_BEHAVIORS[tool].tactic,
              confidence="high",
              anchors=anchors + tools=[tool],
              order=running_counter,
              within_seconds=300 if any SEQUENCE_HINT matches else None
            )
   c. VERB pass:
      - For each (behavior_type, regex) in VERB_PATTERNS:
        - if regex matches:
          - anchors = pick_anchors(sentence, normalized_iocs)
          - if anchors is empty: continue (too vague)
          - emit Behavior(
              behavior_type=behavior_type,
              confidence="medium",
              anchors=anchors,
              order=running_counter,
              within_seconds=300 if sequence hint else None
            )
4. Deduplicate behaviors:
   - key on (behavior_type + tools + file_names + domains)
5. Sort by order and return.

## pick_anchors(sentence, iocs)
- anchors.file_names: any IOC file names that appear in sentence
- anchors.domains: any IOC domains that appear in sentence
- anchors.urls: any IOC URLs that appear in sentence
- anchors.ip_ports: any IOC ip:port values that appear in sentence
- anchors.tools: tool keywords present in sentence
- anchors.sequence_hint: True if sentence contains sequencing words (after/then/followed by/etc.)
