# SIFT-Eye Design Document

Date: 2026-06-14
Hackathon: SANS FIND EVIL (deadline Jun 15, 2026 11:45 PM EDT)

## Overview

SIFT-Eye is an autonomous DFIR agent that runs on the SANS SIFT Workstation. It uses Claude Code as the agentic framework and a custom Python MCP server that wraps SIFT tools as typed, read-only functions. The MCP server is the architectural guardrail — destructive commands physically cannot be invoked because the server doesn't expose them.

## Target Dataset

**The Fred Rocba Case** (Standard Forensic Case from HACKATHON-2026):
- `rocba-cdrive.e01` — 22.1 GB E01 disk image (Fred's C: drive)
- `Rocba-Memory.zip` — 5.3 GB memory dump
- Scenario: Break-in and IP theft at Stark Research Labs. Fred Rocba's system compromised while on vacation.

## Architecture

Hybrid: Claude Code (agentic framework) + Python MCP Server (tool layer)

### Claude Code Layer
- CLAUDE.md defines the analyst persona, investigation methodology, and guardrails
- Skills sequence the investigation phases (triage → timeline → memory → correlate → report)
- Claude Code drives tool selection, self-correction, and narrative generation

### MCP Server Layer
- Python stdio MCP server using `mcp` SDK
- All tools are read-only (no write commands exist)
- Evidence integrity: SHA-256 hash on mount, verified periodically
- Structured audit log: every tool call logged to `audit_log.jsonl`
- Output isolation: all results written to `/tmp/sift-eye/case_XXXX/`

### Tools Exposed

**Disk (Sleuthkit + ewftools):**
- ewfinfo, mmls, fls, icat, file_type, tsk_recover, sorter

**Memory (Volatility 3):**
- vol_pslist, vol_pstree, vol_netscan, vol_cmdline, vol_malfind, vol_dlllist, vol_filescan, vol_handles

**Analysis:**
- hash_file, strings_search, yara_scan, regripper, log2timeline, plaso_parse

**Integrity:**
- hash_evidence, verify_integrity

## Self-Correction Flow

1. Initial triage (filesystem overview, partition layout, OS detection)
2. Timeline generation (log2timeline → plaso → CSV)
3. Artifact deep-dive (registry, prefetch, amcache, browser, event logs)
4. Memory analysis (processes, network, injected code, command history)
5. Cross-correlation — compare disk vs memory findings, flag contradictions
6. Re-run targeted analysis on flagged items
7. Document what changed between passes (the self-correction delta)
8. Generate investigative narrative with artifact citations

## Output Format

- `findings.jsonl` — structured findings with artifact citations
- `audit_log.jsonl` — tool execution trace (timestamp, tool, args, output hash, duration)
- `report.md` — investigative narrative
- `timeline.csv` — super timeline

## Judging Criteria Alignment

| Criterion | How addressed |
|-----------|---------------|
| Autonomous Execution | Claude Code multi-phase triage, no human intervention |
| IR Accuracy | Every finding has artifact citation + confidence level |
| Breadth/Depth | Disk + memory + cross-correlation |
| Constraint Implementation | MCP server is architecturally read-only |
| Audit Trail | audit_log.jsonl traces every finding to tool execution |
| Usability/Docs | README with SIFT setup, MIT license, example output |
