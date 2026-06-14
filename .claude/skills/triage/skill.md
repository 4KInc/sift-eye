---
description: "Run initial disk image triage — evidence intake, partition layout, OS detection, key directories"
---

# Triage Skill

Run initial triage on a disk image. Follow these steps exactly:

## Step 1: Evidence Intake
1. Call `hash_evidence` with all evidence file paths to establish integrity baseline
2. Call `get_case_dir` to note the output directory

## Step 2: Image Metadata
1. Call `disk_ewfinfo` on the E01 image to get case metadata
2. Call `disk_mmls` to identify partitions and their offsets

## Step 3: Filesystem Overview
For the main NTFS partition (typically the largest one):
1. Call `disk_fsstat` with the partition offset to get filesystem details
2. Call `disk_fls` on the root directory to see top-level structure
3. Call `disk_fls` on key directories:
   - Users/ (identify user accounts)
   - Windows/System32/ (check OS version)
   - Program Files/ (installed software)
   - Program Files (x86)/ (32-bit software on 64-bit OS)

## Step 4: Initial Assessment
Document:
- OS type and version
- User accounts found
- Partition layout
- Any immediate red flags (encrypted volumes, wiping tools, etc.)

Write initial findings to findings.jsonl using the Bash tool:
```bash
echo '{"id":"TRIAGE-001","severity":"INFO","title":"System Identification","description":"...","tool_used":"disk_fsstat","confidence":"CONFIRMED"}' >> $CASE_DIR/findings.jsonl
```
