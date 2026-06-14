# Dataset Documentation

## Evidence Source

**The Fred Rocba Case** - Standard Forensic Case from the SANS FIND EVIL Hackathon 2026 dataset.

Download: SANS Egnyte share (HACKATHON-2026 / Standard Forensic Case)

## Evidence Files

| File | Type | Size | Hash |
|------|------|------|------|
| rocba-cdrive.e01 | EnCase E01 disk image | 22.1 GB (81 GB uncompressed) | MD5: 5efc207c85587683e5ca5fa2d5ef1aa4, SHA1: 645dcd29ab039359fbdb6643961478b3d914f21d |
| Rocba-Memory.raw | Raw memory dump | 18 GB | (computed at investigation time) |
| ROCBA-BACKGROUND.pptx | Case background presentation | 38.3 MB | N/A |

## System Details (from evidence)

| Field | Value |
|-------|-------|
| OS | Windows 10 x64, Build 19041/19042 |
| Acquisition Tool | X-Ways Forensics (XWF) 20.1 |
| Disk Acquisition Date | December 18, 2020 |
| Memory Capture Date | November 16, 2020, 02:32:38 UTC |
| System Boot Time | November 11, 2020, 08:13:00 UTC |
| Local IP | 192.168.1.5 |
| User Accounts | fredr (Fred Rocba), srl-h |
| Filesystem | NTFS (single volume, no partition table) |
| CPUs | 4 |

## Case Scenario

Fred Rocba is an employee at Stark Research Labs (SRL). The case involves a break-in and IP theft. Fred was on vacation during part of the relevant timeframe, with his vacation photos syncing to his home system via iCloud.

## What the Agent Found

### Critical Findings
1. **SDelete anti-forensics tool** downloaded from Sysinternals on Nov 14
2. **107+ RDP connections** from 4 external IPs with 4 ESTABLISHED sessions
3. **MRC.exe remote access tool** launched from D:\Tools during the RDP attack window

### High Findings
4. Proprietary files (Project P.E.G.A.S.U.S, VIBRANIUM, ADAMANTIUM) on personal cloud storage
5. Five cloud sync services active (Google Drive, OneDrive x2, iCloud, Dropbox)
6. PowerShell transcripts from remote server BASE-RD-08
7. WorkingFiles.zip suggesting staged data for exfiltration

### Total: 16 structured findings across CRITICAL, HIGH, MEDIUM, LOW, and INFO severities.

## Reproducibility

To reproduce the analysis:
1. Download the evidence files from the SANS HACKATHON-2026 Egnyte share
2. Unzip Rocba-Memory.zip then extract Rocba-Memory.7z to get Rocba-Memory.raw
3. Follow setup instructions in the project README
4. Run: `claude` and instruct it to investigate both evidence files
