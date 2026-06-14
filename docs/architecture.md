# SIFT-Eye Architecture

## System Diagram

```
+------------------------------------------------------------------+
|                    Claude Code (Agentic Framework)                |
|                                                                  |
|  +------------------+    +----------------------------------+    |
|  |    CLAUDE.md      |    |         Skills/                  |    |
|  |                  |    |  triage.md         Phase 1-2      |    |
|  |  Senior analyst  |    |  memory-analysis.md Phase 4       |    |
|  |  persona with    |    |  correlate.md      Phase 5-6     |    |
|  |  7-phase method  |    |  report.md         Phase 7       |    |
|  +------------------+    +----------------------------------+    |
|                                                                  |
|  Autonomous Reasoning: tool selection, self-correction,          |
|  cross-correlation, narrative generation                         |
|                                                                  |
+-----------------------------+------------------------------------+
                              |
                         stdio (MCP)
                              |
+-----------------------------v------------------------------------+
|                 sift-eye-mcp (Python MCP Server)                 |
|                                                                  |
|  +-------------------+  +------------------+  +---------------+  |
|  | Disk Tools (7)    |  | Memory Tools (13)|  | Analysis (8)  |  |
|  |                   |  |                  |  |               |  |
|  | ewfinfo           |  | pslist           |  | hash          |  |
|  | mmls              |  | pstree           |  | strings       |  |
|  | fls               |  | netscan          |  | yara          |  |
|  | icat              |  | cmdline          |  | regripper     |  |
|  | file_type         |  | malfind          |  | log2timeline  |  |
|  | fsstat            |  | dlllist          |  | psort         |  |
|  | tsk_recover       |  | filescan         |  | exiftool      |  |
|  |                   |  | handles          |  | foremost      |  |
|  |                   |  | hivelist         |  |               |  |
|  |                   |  | printkey         |  |               |  |
|  |                   |  | hashdump         |  |               |  |
|  |                   |  | envars           |  |               |  |
|  |                   |  | svcscan          |  |               |  |
|  +-------------------+  +------------------+  +---------------+  |
|                                                                  |
|  +-----------------------------------------------------------+  |
|  |              Integrity Layer (ARCHITECTURAL)               |  |
|  |                                                            |  |
|  |  - SHA-256 evidence hashing before/after analysis          |  |
|  |  - Output isolation: all results to /tmp/sift-eye/case_*  |  |
|  |  - _is_safe_output_path() enforces write boundaries       |  |
|  |  - NO write commands to evidence paths exist in codebase   |  |
|  +-----------------------------------------------------------+  |
|                                                                  |
|  +-----------------------------------------------------------+  |
|  |              Audit Logger (ARCHITECTURAL)                  |  |
|  |                                                            |  |
|  |  Every tool call logged to audit_log.jsonl:                |  |
|  |  {sequence, timestamp, tool, arguments, output_hash,       |  |
|  |   output_bytes, duration_ms, success, error}               |  |
|  +-----------------------------------------------------------+  |
|                                                                  |
+-----------------------------+------------------------------------+
                              |
                     subprocess calls
                              |
              +---------------+----------------+
              |               |                |
        +-----v-----+  +-----v------+  +------v------+
        | Sleuthkit  |  | Volatility |  | RegRipper   |
        | ewftools   |  | 3          |  | YARA        |
        |            |  |            |  | ExifTool    |
        | (read-only |  | (read-only |  | Plaso       |
        |  disk ops) |  |  mem ops)  |  | Foremost    |
        +------------+  +------------+  +-------------+
              |               |                |
        +-----v-----+  +-----v------+         |
        | E01 Disk   |  | Memory     |         |
        | Image      |  | Dump       |         |
        | (read-only)|  | (read-only)|         |
        +------------+  +------------+         |
                                               |
                                    +----------v---------+
                                    | /tmp/sift-eye/     |
                                    | case_<timestamp>/  |
                                    |                    |
                                    | findings.jsonl     |
                                    | audit_log.jsonl    |
                                    | report.md          |
                                    | timeline.csv       |
                                    | artifacts/         |
                                    +--------------------+
```

## Security Boundaries

| Boundary | Type | Enforcement |
|----------|------|-------------|
| Evidence files are never written to | **Architectural** | MCP server exposes zero write operations on evidence paths. `_is_safe_output_path()` rejects any output not in `/tmp/sift-eye/`. No `dd`, `mount -o rw`, `rm`, or write commands exist in the codebase. |
| All outputs isolated to case directory | **Architectural** | `SIFT_EYE_CASE_DIR` env var or auto-generated `/tmp/sift-eye/case_<timestamp>/`. Code enforces via path validation. |
| Evidence integrity verified cryptographically | **Architectural** | SHA-256 hash computed before analysis and verifiable after. Stored in `evidence_hashes.json`. |
| Every tool call audited | **Architectural** | `AuditLogger` wraps every MCP tool. Logs timestamp, arguments, output hash, duration. Cannot be bypassed from the agent layer. |
| Investigation methodology | Prompt-based | CLAUDE.md defines 7-phase approach. Skills guide each phase. Agent can deviate but methodology is the default. |
| Accuracy standards | Prompt-based | CLAUDE.md requires artifact citations, confidence levels, and explicit distinction between findings and inferences. |

## Data Flow

```
Evidence Files (read-only)
     |
     v
MCP Server (tool wrappers)
     |
     +---> Audit Logger ---> audit_log.jsonl
     |
     v
Claude Code (reasoning + correlation)
     |
     +---> findings.jsonl (structured findings)
     +---> report.md (investigative narrative)
```

## Self-Correction Flow

```
Phase 1-4: Independent analysis (disk triage, timeline, artifacts, memory)
     |
     v
Phase 5: Cross-correlation
     |
     +---> Compare disk findings vs memory findings
     +---> Flag contradictions
     +---> Run targeted tools to resolve
     +---> Document: EXPECTED vs FOUND vs RESOLUTION
     |
     v
Phase 6: Updated findings with corrected information
     |
     v
Phase 7: Report with self-correction log
```
