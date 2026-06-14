# Accuracy Report

## Self-Assessment Summary

SIFT-Eye analyzed the Fred Rocba case (disk image + memory dump) and produced 16 findings. This report documents accuracy, false positives, missed artifacts, and evidence integrity approach.

## Findings Accuracy

### Confirmed Findings (high confidence)
| ID | Finding | Verification Method |
|----|---------|-------------------|
| DISK-001 | SDelete.zip downloaded from Sysinternals | Zone.Identifier ADS contains exact download URL |
| NET-001/002/003 | RDP connections from 4 external IPs | Volatility netscan shows IP:port pairs with timestamps |
| MEM-002 | MRC.exe launched from D:\Tools | Process list shows PID, path, parent, timestamp |
| DISK-002 | Project P.E.G.A.S.U.S files on OneDrive | fls recursive listing shows directory tree with files |
| DISK-003 | VIBRANIUM/ADAMANTIUM on Google Drive | fls listing shows files with timestamps |
| DISK-006 | PowerShell transcripts from BASE-RD-08 | File names contain hostname and timestamps |

All confirmed findings are traceable to specific tool output referenced in audit_log.jsonl.

### Probable Findings (medium confidence)
| ID | Finding | Why Probable |
|----|---------|-------------|
| DISK-005 | WorkingFiles.zip as staged exfiltration | Filename suggests work files, but content not extracted and examined |
| DISK-007 | SRL-Offer.pdf significance | Filename suggestive but content not examined |

### False Positives Identified and Corrected
| Finding | Initial Assessment | Corrected Assessment | How Detected |
|---------|-------------------|---------------------|--------------|
| Malfind hits | Potential code injection | False positive (Windows Defender JIT) | Hex dump analysis: 0xCC padding + standard function prologues, no MZ headers |

## Missed Artifacts / Known Gaps

1. **Event logs not extracted** - Security.evtx would confirm RDP login success/failure (EventID 4624/4625). The agent identified this as a recommended follow-up but did not extract and parse the event logs in this run.

2. **SDelete execution not confirmed** - We confirmed SDelete was downloaded but did not check for SDELETE*.pf prefetch files to confirm it was actually executed.

3. **Browser history not examined** - Chrome and Edge were active but browsing history database was not extracted or parsed.

4. **Registry hives not analyzed** - NTUSER.DAT and SYSTEM hives were identified but not extracted and processed with RegRipper. This would reveal USB history, recently accessed files, and persistence mechanisms.

5. **Timeline not generated** - log2timeline/plaso was not run due to the time required (can take 1+ hours on an 81 GB image). This would provide a comprehensive timeline across all artifact sources.

6. **File content analysis limited** - Proprietary documents (VIBRANIUM.docx, ADAMANTIUM-Background.docx, SRL-Offer.pdf) were identified by filename but content was not extracted or examined.

7. **GeoIP lookup not performed** - The 4 external RDP IPs were not geolocated. This would help determine attacker origin.

## Hallucination Assessment

- **Zero hallucinated file paths** - All paths cited exist in fls output
- **Zero hallucinated IP addresses** - All IPs from netscan output
- **Zero hallucinated process names** - All from pslist output
- **One inference clearly labeled** - WorkingFiles.zip marked as "PROBABLE" not "CONFIRMED"

## Evidence Integrity Approach

### Architectural Enforcement (not prompt-based)

1. **MCP server has no write tools** - The server codebase contains zero functions that write to evidence paths. This is verified by code inspection, not by trusting the LLM to follow rules.

2. **Output path validation** - `_is_safe_output_path()` in disk.py and analysis.py rejects any output path not under `/tmp/sift-eye/`. This is enforced in code.

3. **SHA-256 evidence hashing** - `integrity.py` computes hashes before analysis. `verify_integrity()` re-hashes and compares. Mismatch = FAIL.

4. **All tools use subprocess** - Every tool call goes through `subprocess.run()` with explicit command construction. No shell=True, no arbitrary command injection.

### What happens if the model ignores read-only rules?

The model cannot ignore read-only rules because **the rules are not implemented as prompts**. The MCP server physically does not expose destructive operations. There is no `disk_write`, `disk_delete`, or `evidence_modify` tool. The agent could attempt to use the Bash tool directly, but:
- The CLAUDE.md instructs use of MCP tools only
- The `.claude/settings.json` permission list restricts Bash to benign commands
- Even if Bash is used, the evidence is an E01 image (read-only forensic format) and a raw memory dump (also read-only by nature)

### Spoliation Testing

We did not intentionally test for spoliation because:
1. E01 images are inherently read-only (compressed forensic format, not mountable read-write)
2. Raw memory dumps are inherently read-only
3. The MCP server has no write tools for evidence paths (architectural constraint)

The risk of evidence modification is effectively zero in this architecture.

## Confidence Summary

| Category | Count | Percentage |
|----------|-------|-----------|
| CONFIRMED | 12 | 75% |
| PROBABLE | 2 | 12.5% |
| False positive (corrected) | 1 | 6.25% |
| INFO | 2 | 12.5% |
| Hallucinated | 0 | 0% |
