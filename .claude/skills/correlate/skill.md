---
description: "Cross-correlate disk and memory findings — the self-correction phase"
---

# Cross-Correlation & Self-Correction Skill

This is the MOST IMPORTANT skill. Compare findings from disk analysis and memory analysis to find contradictions, resolve them, and demonstrate self-correction.

## Step 1: Gather Existing Findings
Read the findings.jsonl file to review all findings so far. Categorize them:
- Disk-only findings (from triage, timeline, artifact analysis)
- Memory-only findings (from memory analysis)
- Findings present in both sources

## Step 2: Cross-Reference Processes
For each suspicious process found in memory:
1. Search the disk for the executable (use `disk_fls` with the expected path)
2. If found on disk: check timestamps (creation, modification) — do they make sense?
3. If NOT found on disk: this is suspicious — possible in-memory-only malware or deleted executable
4. Document the discrepancy

For each suspicious executable found on disk (prefetch, amcache):
1. Check if it appears in the memory process list
2. If in memory: consistent — process was running at time of capture
3. If NOT in memory: process may have exited before memory capture — check prefetch timestamps vs memory capture time
4. Document the finding

## Step 3: Cross-Reference Network
For each network connection in memory:
1. Identify the owning process
2. Search disk for related artifacts (browser history, DNS cache, firewall logs)
3. Check if the destination IP/domain appears in any disk artifacts
4. Document matches and mismatches

## Step 4: Cross-Reference Registry
For each persistence mechanism found in registry (disk):
1. Check if the referenced executable exists on disk
2. Check if the referenced executable appears in memory
3. If registry points to a file that doesn't exist: possible deleted malware
4. Document the finding

## Step 5: Timeline Consistency
1. Compare timestamps across sources:
   - Prefetch execution times vs process creation times in memory
   - File modification times vs event log entries
   - Browser history timestamps vs network connection timestamps
2. Flag any temporal impossibilities (file modified after system shutdown, etc.)

## Step 6: Self-Correction Report
For each contradiction or discrepancy found:
1. State: "EXPECTED: [X] but FOUND: [Y]"
2. Formulate hypothesis: "This could mean: [A], [B], or [C]"
3. Run targeted tool to test hypothesis
4. State resolution: "RESOLUTION: [conclusion] based on [evidence]"
5. Update findings with corrected information

Write a self-correction summary section that documents:
- Total contradictions found
- Contradictions resolved
- Contradictions remaining (with explanations)
- How the analysis changed based on self-correction
