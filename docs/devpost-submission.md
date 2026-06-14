# SIFT-Eye: Autonomous DFIR Agent

## What it does

SIFT-Eye is an autonomous digital forensics agent that investigates disk images and memory dumps without human intervention. It uses Claude Code as the agentic framework and a custom Python MCP server that wraps SIFT Workstation tools as typed, read-only functions.

Given evidence files, SIFT-Eye:
- Hashes evidence for integrity verification before touching anything
- Runs a 7-phase investigation (triage, filesystem analysis, artifact extraction, memory forensics, cross-correlation, self-correction, report generation)
- Produces structured findings with artifact citations, confidence levels, and severity ratings
- Cross-correlates disk and memory findings to catch contradictions and correct its own analysis
- Generates an investigative narrative that reads like a senior analyst wrote it

On the Fred Rocba case (SANS HACKATHON-2026 Standard Forensic Case), SIFT-Eye autonomously identified 21 findings including:
- SDelete anti-forensics tool downloaded AND executed (confirmed via Prefetch)
- 107+ RDP connections from 4 external IPs with 4 active sessions at time of capture
- MRC.exe remote access tool launched from D:\Tools during the RDP attack window
- Proprietary Stark Research Labs IP (Project P.E.G.A.S.U.S, VIBRANIUM, ADAMANTIUM) synced to personal cloud storage
- Classified documents (DGSE Intel Analysis, weapons system data) accessed from the subject's machine
- Deleted Outlook PST archive in Recycle Bin
- BitLocker encryption wizard executed

It also correctly identified Windows Defender malfind hits as false positives and documented the reasoning.

## How we built it

**Architecture: Claude Code + custom MCP server (hybrid)**

The insight is that evidence protection should be architectural, not prompt-based. Telling an LLM "don't modify evidence" is a prompt restriction that can be ignored. Building an MCP server that physically has no write commands is a code constraint that cannot be bypassed.

**MCP Server (Python, 32 tools):**
- 7 disk tools wrapping Sleuthkit and ewftools (ewfinfo, mmls, fls, icat, fsstat, file_type, tsk_recover)
- 13 memory tools wrapping Volatility 3 (pslist, pstree, netscan, cmdline, malfind, dlllist, filescan, handles, hivelist, printkey, hashdump, envars, svcscan)
- 8 analysis tools (hash, strings, yara, regripper, log2timeline, psort, exiftool, foremost)
- 4 integrity tools (hash_evidence, check_integrity, get_case_dir, get_audit_stats)
- Every tool call is automatically logged to audit_log.jsonl with timestamp, arguments, output hash, and duration

**Claude Code layer:**
- CLAUDE.md defines a senior analyst persona with a 7-phase investigation methodology
- Skills guide each phase: triage, memory-analysis, correlate (self-correction), report
- The agent decides which tools to call, in what order, and what to do with the results

**Self-correction implementation:**
Phase 5 (cross-correlation) compares findings across disk and memory sources. When contradictions are found, the agent:
1. Documents EXPECTED vs FOUND
2. Formulates hypotheses
3. Runs targeted tools to test each hypothesis
4. Documents the resolution and updates findings

Example from this investigation: malfind flagged RWX memory regions in MsMpEng.exe. The agent examined the hex dump, identified 0xCC padding patterns (debug breakpoints) and standard function prologues, correctly classified them as Windows Defender JIT false positives, and documented the reasoning.

## Challenges we ran into

**SIFT VM on Apple Silicon:** The SIFT Workstation OVA is x86_64. Running it under QEMU emulation on ARM was unusably slow. We pivoted to installing the forensic tools natively on macOS via Homebrew (sleuthkit, libewf, volatility3). The architecture is platform-agnostic since the MCP server wraps CLI tools.

**Volatility 3 on large memory dumps:** The 18 GB memory dump takes significant time for some plugins (svcscan, filescan). We parallelized independent plugins across multiple agents to reduce wall-clock time.

**E01 image without partition table:** The evidence disk image is a logical acquisition (single NTFS volume, no partition table). mmls returns empty. The agent needed to recognize this and use fls directly without a partition offset. This is exactly the kind of edge case that tests autonomous reasoning.

**Context window management:** Full fls recursive listings and Volatility outputs can be massive. The MCP server truncates outputs to prevent context window overflow while preserving the most forensically relevant data.

## What we learned

1. **Architectural guardrails beat prompt guardrails.** Judges specifically call this out in the criteria. A read-only MCP server is provably safe. A prompt saying "don't modify evidence" is not.

2. **Cross-source correlation is where the real value is.** Any tool can list processes or files. The differentiation is finding contradictions between disk and memory that a human analyst would catch.

3. **Honest accuracy reporting builds trust.** We documented 7 known gaps (event logs not parsed, browser history not extracted, etc.) and 1 false positive that was corrected. Practitioners trust tools that acknowledge limitations.

4. **The "find" in Find Evil is the easy part.** The hard part is distinguishing confirmed findings from inferences, citing specific artifacts, and producing a narrative that would hold up in an investigation report.

## What's next

- **Event log parsing:** Extract and analyze Security.evtx for RDP login events (EventID 4624/4625)
- **Registry analysis:** Run RegRipper against extracted hives for USB history, UserAssist, and persistence mechanisms
- **Browser forensics:** Parse Chrome and Firefox SQLite databases for browsing history and downloads
- **Super timeline:** Full log2timeline/plaso run for comprehensive cross-artifact timeline
- **PST recovery:** Extract the deleted Outlook archive from the Recycle Bin
- **GeoIP enrichment:** Locate the 4 external RDP attacker IPs
- **YARA scanning:** Run malware signature scans against extracted executables

## Built With

- Claude Code (agentic framework)
- Python MCP server (mcp SDK)
- Sleuthkit (disk forensics)
- Volatility 3 (memory forensics)
- ewftools (E01 image handling)
- SANS SIFT Workstation tools
