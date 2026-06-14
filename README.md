# SIFT-Eye: Autonomous DFIR Agent

An autonomous digital forensics and incident response (DFIR) agent built on the SANS SIFT Workstation. SIFT-Eye uses Claude Code as the agentic framework and a custom Python MCP server that wraps 200+ SIFT tools as typed, **architecturally read-only** functions.

## Architecture

```
Claude Code (Agentic Framework)
├── CLAUDE.md — Senior analyst persona + investigation methodology
├── Skills — Phased investigation (triage → timeline → memory → correlate → report)
│
└── MCP Client ──── stdio ──── sift-eye-mcp (Python MCP Server)
                                ├── Disk tools (Sleuthkit, ewftools)
                                ├── Memory tools (Volatility 3)
                                ├── Analysis tools (RegRipper, plaso, YARA, strings)
                                ├── Integrity layer (SHA-256 evidence hashing)
                                └── Audit logger (every tool call → audit_log.jsonl)
```

### Why Hybrid?

- **Claude Code** provides autonomous reasoning, self-correction, and narrative generation
- **MCP Server** provides architectural evidence protection — destructive commands physically cannot be invoked because the server doesn't expose them. This is not a prompt restriction; it's a code constraint.

### Security Boundaries

| Boundary | Enforcement | Type |
|----------|-------------|------|
| Evidence read-only | MCP server has no write tools for evidence paths | **Architectural** |
| Output isolation | All outputs to `/tmp/sift-eye/case_*/` only | **Architectural** |
| Evidence integrity | SHA-256 hash before/after analysis | **Architectural** |
| Investigation methodology | CLAUDE.md + Skills | Prompt-based |
| Accuracy standards | CLAUDE.md rules | Prompt-based |

## Setup on SIFT Workstation

### Prerequisites

- SANS SIFT Workstation (VM or bare metal) — [Download](https://www.sans.org/tools/sift-workstation/)
- Protocol SIFT installed: `curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`
- Claude Code: `npm install -g @anthropic-ai/claude-code`
- Python 3.11+

### Installation

```bash
# Clone the repository
git clone https://github.com/4KInc/sift-eye.git
cd sift-eye

# Install the MCP server
cd mcp-server
pip install -e .
cd ..

# Verify MCP server starts
python3 -m sift_eye_mcp.server --help
```

### Running an Investigation

```bash
# Start Claude Code in the sift-eye directory
cd sift-eye
claude

# Then tell the agent what to investigate:
# "Investigate the disk image at /evidence/rocba-cdrive.e01 and the memory dump at /evidence/rocba-memory.raw"
```

Claude Code will:
1. Hash all evidence files (integrity baseline)
2. Run initial triage (partitions, OS, user accounts)
3. Generate a super timeline
4. Analyze Windows artifacts (registry, prefetch, event logs)
5. Analyze memory (processes, network, injected code)
6. Cross-correlate disk and memory findings (self-correction)
7. Generate an investigative report with artifact citations

### Manual Skill Invocation

You can also invoke individual investigation phases:

```
/triage              — Run initial disk triage
/memory-analysis     — Analyze memory dump
/correlate           — Cross-correlate and self-correct
/report              — Generate final report
```

## Output

All output goes to `/tmp/sift-eye/case_<timestamp>/`:

| File | Purpose |
|------|---------|
| `evidence_hashes.json` | SHA-256 hashes of all evidence files |
| `findings.jsonl` | Structured findings (one per line) |
| `audit_log.jsonl` | Every tool call with timestamp, args, output hash, duration |
| `report.md` | Investigative narrative |
| `timeline.csv` | Super timeline (if generated) |
| `artifacts/` | Extracted artifacts |

### Finding Format

```json
{
  "id": "MEM-003",
  "severity": "HIGH",
  "title": "Injected code detected in PID 1234",
  "description": "MZ header found in non-image memory region of explorer.exe",
  "artifact_path": "memory @ 0x7ff12340000",
  "tool_used": "mem_malfind",
  "confidence": "CONFIRMED",
  "raw_output_ref": "audit_log.jsonl:sequence:42"
}
```

### Audit Log Format

```json
{
  "sequence": 42,
  "timestamp": "2026-06-14T20:15:33.123Z",
  "tool": "mem_malfind",
  "arguments": {"memory_path": "/evidence/rocba-memory.raw"},
  "output_hash": "a1b2c3d4...",
  "output_bytes": 15234,
  "duration_ms": 3421.5,
  "success": true
}
```

## Self-Correction

SIFT-Eye's cross-correlation phase compares findings across evidence sources and documents contradictions:

1. **Expected vs Found** — What the agent expected to find vs what it actually found
2. **Hypothesis** — Possible explanations for the discrepancy
3. **Test** — Targeted tool execution to resolve the contradiction
4. **Resolution** — Updated finding with corrected information

Example:
> EXPECTED: Process `svchost.exe` (PID 1234) found in prefetch should appear in memory process list.
> FOUND: Not in mem_pslist output.
> HYPOTHESIS: Process exited before memory capture; OR anti-forensics hiding the process.
> TEST: Checked mem_pstree for orphaned children; checked prefetch timestamp vs memory capture time.
> RESOLUTION: Prefetch last-run time (14:32:05) is 3 hours before memory capture (17:45:12). Process executed and exited normally. Not suspicious.

## MCP Server Tools (35 total)

### Evidence Integrity (4)
`hash_evidence`, `check_integrity`, `get_case_dir`, `get_audit_stats`

### Disk Forensics (7)
`disk_ewfinfo`, `disk_mmls`, `disk_fls`, `disk_icat`, `disk_file_type`, `disk_fsstat`, `disk_recover_deleted`

### Memory Forensics (13)
`mem_pslist`, `mem_pstree`, `mem_netscan`, `mem_cmdline`, `mem_malfind`, `mem_dlllist`, `mem_filescan`, `mem_handles`, `mem_hivelist`, `mem_printkey`, `mem_hashdump`, `mem_envars`, `mem_svcscan`

### Analysis (8)
`compute_hash`, `search_strings`, `run_yara`, `run_regripper`, `run_log2timeline`, `run_psort`, `run_exiftool`, `carve_files`

## Tested Against

**The Fred Rocba Case** (SANS HACKATHON-2026 Standard Forensic Case):
- `rocba-cdrive.e01` — 22.1 GB E01 disk image (Windows system)
- `Rocba-Memory.zip` — 5.3 GB memory dump
- Scenario: Break-in and IP theft at Stark Research Labs

## License

MIT
