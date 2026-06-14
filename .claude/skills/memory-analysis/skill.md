---
description: "Analyze a memory dump with Volatility 3 — processes, network, injected code, registry"
---

# Memory Analysis Skill

Analyze a memory dump using Volatility 3. Follow these steps:

## Step 1: Process Analysis
1. Call `mem_pslist` to get the full process list
2. Call `mem_pstree` to see parent-child relationships
3. Look for:
   - Processes with unusual names or paths
   - Processes spawned by cmd.exe, powershell.exe, or wscript.exe
   - Processes with no parent (orphaned)
   - Multiple instances of singleton processes (svchost.exe is normal, lsass.exe is not)

## Step 2: Network Analysis
1. Call `mem_netscan` to find network connections
2. Look for:
   - Connections to external IPs (non-RFC1918)
   - Unusual listening ports
   - Connections from unexpected processes
   - Known malicious ports (4444, 5555, 8080 from non-browser processes)

## Step 3: Command Line Analysis
1. Call `mem_cmdline` to see what commands were run
2. Look for:
   - Encoded PowerShell commands (-enc, -e)
   - Net user/net group commands (reconnaissance)
   - Certutil, bitsadmin (download abuse)
   - Reg add/reg export (persistence)

## Step 4: Code Injection Detection
1. Call `mem_malfind` to detect injected code
2. For any suspicious PID found, call `mem_dlllist` with that PID
3. Look for:
   - MZ headers in non-image regions
   - RWX memory permissions
   - Suspicious DLLs loaded from temp directories

## Step 5: Registry from Memory
1. Call `mem_hivelist` to find loaded registry hives
2. Call `mem_printkey` for persistence locations:
   - `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
   - `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
   - `SYSTEM\CurrentControlSet\Services`

## Step 6: Services
1. Call `mem_svcscan` to list services
2. Look for services with unusual binary paths or display names

## Step 7: Environment Variables
1. For suspicious PIDs, call `mem_envars` to check environment context

Write all findings to findings.jsonl with appropriate severity and confidence levels.
