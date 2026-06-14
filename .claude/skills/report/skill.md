---
description: "Generate the final investigative narrative report"
---

# Report Generation Skill

Generate the final investigative report. The report must be a narrative — not a tool output dump.

## Report Structure

Write the report to `$CASE_DIR/report.md` with this structure:

### 1. Executive Summary (3-5 sentences)
- What happened
- Who was affected
- What evidence supports the conclusion
- Confidence level of the overall assessment

### 2. Case Information
- Evidence files analyzed (with SHA-256 hashes)
- Tools used (from audit stats)
- Analysis timeframe
- Analyst: SIFT-Eye Autonomous DFIR Agent

### 3. Timeline of Events
Chronological narrative of what happened, based on timeline analysis.
Each event must cite:
- Timestamp
- Artifact source (file path, registry key, memory offset)
- Tool that produced the finding
- Confidence level

### 4. Key Findings
For each finding:
- **Finding ID**: From findings.jsonl
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Description**: What was found
- **Evidence**: Specific artifact, tool, and output reference
- **Confidence**: CONFIRMED / PROBABLE / POSSIBLE / UNVERIFIED

### 5. Indicators of Compromise (IOCs)
List all IOCs discovered:
- File hashes (MD5, SHA-256)
- IP addresses
- Domain names
- File paths
- Registry keys
- User accounts

### 6. Self-Correction Log
Document the cross-correlation phase:
- Contradictions found between disk and memory
- How each was resolved
- What changed in the analysis as a result

### 7. What Was NOT Found
Document negative findings — what you checked but did NOT find evidence of:
- No evidence of X
- Checked Y but found Z instead
This proves thoroughness and prevents accusation of tunnel vision.

### 8. Recommendations
Based on findings, recommend:
- Immediate containment actions
- Further investigation areas
- Evidence preservation priorities

### 9. Appendix
- Evidence integrity verification (before/after hashes)
- Full tool execution statistics
- Reference to audit_log.jsonl for complete trace

## Rules
- Every factual claim must have an artifact citation
- Distinguish CONFIRMED findings from INFERENCES
- Use "Based on [evidence], this suggests [conclusion]" for inferences
- Never state conclusions without evidence
- Run `check_integrity` one final time and include the result
- Run `get_audit_stats` and include tool usage summary
