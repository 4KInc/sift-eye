"""SIFT-Eye MCP Server — read-only forensic tool wrappers for SIFT Workstation.

This server exposes SIFT Workstation tools as typed MCP functions.
All tools are READ-ONLY. No destructive commands exist.
Every tool invocation is logged to audit_log.jsonl.
"""

import os
import time
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from .audit import AuditLogger
from .integrity import hash_evidence_files, verify_integrity
from .tools import analysis, disk, memory

# Case output directory
CASE_DIR = os.environ.get(
    "SIFT_EYE_CASE_DIR",
    f"/tmp/sift-eye/case_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
)

mcp = FastMCP("sift-eye-mcp")

audit = AuditLogger(CASE_DIR)


def _timed_call(tool_name: str, arguments: dict, fn, *args, **kwargs) -> str:
    """Execute a tool function with timing and audit logging."""
    start = time.monotonic()
    try:
        result = fn(*args, **kwargs)
        duration = (time.monotonic() - start) * 1000
        audit.log_tool_call(tool_name, arguments, result, duration, success=True)
        return result
    except Exception as e:
        duration = (time.monotonic() - start) * 1000
        error_msg = f"[ERROR] {type(e).__name__}: {e}"
        audit.log_tool_call(tool_name, arguments, error_msg, duration, success=False, error=str(e))
        return error_msg


# ─── Evidence Integrity Tools ───────────────────────────────────────────────

@mcp.tool()
def hash_evidence(evidence_paths: list[str]) -> str:
    """Hash all evidence files (SHA-256) and save to evidence_hashes.json. Run this FIRST before any analysis to establish evidence integrity baseline."""
    args = {"evidence_paths": evidence_paths}
    result = hash_evidence_files(evidence_paths, CASE_DIR)
    lines = [f"Evidence hashes saved to {CASE_DIR}/evidence_hashes.json\n"]
    for path, info in result.items():
        if "error" in info:
            lines.append(f"  {path}: ERROR - {info['error']}")
        else:
            lines.append(f"  {path}: {info['hash']} ({info['size_bytes']} bytes)")
    output = "\n".join(lines)
    audit.log_tool_call("hash_evidence", args, output, 0, success=True)
    return output


@mcp.tool()
def check_integrity() -> str:
    """Re-hash evidence files and compare against stored hashes. Detects any evidence modification."""
    result = verify_integrity(CASE_DIR)
    lines = [f"Integrity check: {result['status']}\n"]
    for path, info in result.get("files", {}).items():
        lines.append(f"  {path}: {info['status']}")
        if info["status"] == "FAIL":
            lines.append(f"    REASON: {info.get('reason', 'unknown')}")
    output = "\n".join(lines)
    audit.log_tool_call("check_integrity", {}, output, 0, success=result["status"] == "PASS")
    return output


@mcp.tool()
def get_case_dir() -> str:
    """Get the current case output directory path."""
    return CASE_DIR


@mcp.tool()
def get_audit_stats() -> str:
    """Get summary statistics of all tool calls made during this investigation."""
    stats = audit.get_stats()
    lines = [f"Total tool calls: {stats['total_calls']}", f"Total duration: {stats['total_duration_ms']}ms", f"Errors: {stats['errors']}", "\nTool usage:"]
    for tool, count in stats["tools_used"]:
        lines.append(f"  {tool}: {count}")
    return "\n".join(lines)


# ─── Disk Forensic Tools (Sleuthkit + ewftools) ────────────────────────────

@mcp.tool()
def disk_ewfinfo(image_path: str) -> str:
    """Get metadata from an E01/EWF forensic image (case number, examiner, media size, hash)."""
    return _timed_call("disk_ewfinfo", {"image_path": image_path}, disk.ewfinfo, image_path)


@mcp.tool()
def disk_mmls(image_path: str) -> str:
    """Display partition layout of a disk image. Shows partition table, offsets, sizes."""
    return _timed_call("disk_mmls", {"image_path": image_path}, disk.mmls, image_path)


@mcp.tool()
def disk_fls(
    image_path: str,
    inode: str = "",
    partition_offset: str = "",
    recursive: bool = False,
    deleted_only: bool = False,
) -> str:
    """List files and directories in a disk image. Use partition_offset from mmls output. Set recursive=True to list all files, deleted_only=True for deleted files only."""
    args = {"image_path": image_path, "inode": inode, "partition_offset": partition_offset, "recursive": recursive, "deleted_only": deleted_only}
    return _timed_call("disk_fls", args, disk.fls, image_path, inode, partition_offset, recursive, deleted_only)


@mcp.tool()
def disk_icat(image_path: str, inode: str, partition_offset: str = "", output_path: str = "") -> str:
    """Extract a file from a disk image by inode number. Provide output_path (within /tmp/sift-eye/) to save, or omit to preview content."""
    args = {"image_path": image_path, "inode": inode, "partition_offset": partition_offset, "output_path": output_path}
    return _timed_call("disk_icat", args, disk.icat, image_path, inode, partition_offset, output_path)


@mcp.tool()
def disk_file_type(image_path: str, inode: str, partition_offset: str = "") -> str:
    """Determine the file type of a file in a disk image by inode (magic bytes detection)."""
    args = {"image_path": image_path, "inode": inode, "partition_offset": partition_offset}
    return _timed_call("disk_file_type", args, disk.file_type, image_path, inode, partition_offset)


@mcp.tool()
def disk_fsstat(image_path: str, partition_offset: str = "") -> str:
    """Display filesystem details (type, block size, volume label, creation time, etc.)."""
    args = {"image_path": image_path, "partition_offset": partition_offset}
    return _timed_call("disk_fsstat", args, disk.fsstat, image_path, partition_offset)


@mcp.tool()
def disk_recover_deleted(image_path: str, output_dir: str, partition_offset: str = "") -> str:
    """Recover deleted files from a disk image. Output directory must be within /tmp/sift-eye/."""
    args = {"image_path": image_path, "output_dir": output_dir, "partition_offset": partition_offset}
    return _timed_call("disk_recover_deleted", args, disk.tsk_recover, image_path, output_dir, partition_offset)


# ─── Memory Forensic Tools (Volatility 3) ──────────────────────────────────

@mcp.tool()
def mem_pslist(memory_path: str) -> str:
    """List running processes from memory dump (PID, PPID, name, create time, exit time)."""
    return _timed_call("mem_pslist", {"memory_path": memory_path}, memory.vol_pslist, memory_path)


@mcp.tool()
def mem_pstree(memory_path: str) -> str:
    """Show process tree from memory dump (parent-child relationships)."""
    return _timed_call("mem_pstree", {"memory_path": memory_path}, memory.vol_pstree, memory_path)


@mcp.tool()
def mem_netscan(memory_path: str) -> str:
    """Scan for network connections and listening sockets in memory."""
    return _timed_call("mem_netscan", {"memory_path": memory_path}, memory.vol_netscan, memory_path)


@mcp.tool()
def mem_cmdline(memory_path: str) -> str:
    """Show command-line arguments for each process in memory."""
    return _timed_call("mem_cmdline", {"memory_path": memory_path}, memory.vol_cmdline, memory_path)


@mcp.tool()
def mem_malfind(memory_path: str) -> str:
    """Detect injected code and suspicious memory regions (PE headers in non-image sections)."""
    return _timed_call("mem_malfind", {"memory_path": memory_path}, memory.vol_malfind, memory_path)


@mcp.tool()
def mem_dlllist(memory_path: str, pid: int | None = None) -> str:
    """List loaded DLLs for processes. Optionally filter by PID."""
    return _timed_call("mem_dlllist", {"memory_path": memory_path, "pid": pid}, memory.vol_dlllist, memory_path, pid)


@mcp.tool()
def mem_filescan(memory_path: str) -> str:
    """Scan for file objects in memory (finds open files, mapped files, recently accessed files)."""
    return _timed_call("mem_filescan", {"memory_path": memory_path}, memory.vol_filescan, memory_path)


@mcp.tool()
def mem_handles(memory_path: str, pid: int | None = None) -> str:
    """List open handles for processes (files, registry keys, mutexes). Optionally filter by PID."""
    return _timed_call("mem_handles", {"memory_path": memory_path, "pid": pid}, memory.vol_handles, memory_path, pid)


@mcp.tool()
def mem_hivelist(memory_path: str) -> str:
    """List registry hives found in memory."""
    return _timed_call("mem_hivelist", {"memory_path": memory_path}, memory.vol_hivelist, memory_path)


@mcp.tool()
def mem_printkey(memory_path: str, key: str) -> str:
    """Print a specific registry key and its values from memory. Key format: 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'."""
    return _timed_call("mem_printkey", {"memory_path": memory_path, "key": key}, memory.vol_printkey, memory_path, key)


@mcp.tool()
def mem_hashdump(memory_path: str) -> str:
    """Extract password hashes from memory (SAM + SYSTEM hives)."""
    return _timed_call("mem_hashdump", {"memory_path": memory_path}, memory.vol_hashdump, memory_path)


@mcp.tool()
def mem_envars(memory_path: str, pid: int | None = None) -> str:
    """Display environment variables for processes. Optionally filter by PID."""
    return _timed_call("mem_envars", {"memory_path": memory_path, "pid": pid}, memory.vol_envars, memory_path, pid)


@mcp.tool()
def mem_svcscan(memory_path: str) -> str:
    """Scan for Windows services in memory (name, display name, state, binary path)."""
    return _timed_call("mem_svcscan", {"memory_path": memory_path}, memory.vol_svcscan, memory_path)


# ─── Analysis Tools ────────────────────────────────────────────────────────

@mcp.tool()
def compute_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Compute hash of a file. Algorithms: sha256 (default), md5, sha1."""
    return _timed_call("compute_hash", {"file_path": file_path, "algorithm": algorithm}, analysis.hash_file, file_path, algorithm)


@mcp.tool()
def search_strings(file_path: str, min_length: int = 4, encoding: str = "auto", grep: str = "") -> str:
    """Extract strings from a file. Use grep to filter for specific patterns (e.g., 'http', 'password', '.exe')."""
    args = {"file_path": file_path, "min_length": min_length, "encoding": encoding, "grep": grep}
    return _timed_call("search_strings", args, analysis.strings_search, file_path, min_length, encoding, grep)


@mcp.tool()
def run_yara(rules_path: str, target_path: str) -> str:
    """Scan a file or directory with YARA rules for malware signatures."""
    return _timed_call("run_yara", {"rules_path": rules_path, "target_path": target_path}, analysis.yara_scan, rules_path, target_path)


@mcp.tool()
def run_regripper(hive_path: str, plugin: str = "") -> str:
    """Run RegRipper against a Windows registry hive. Omit plugin to run all applicable plugins."""
    return _timed_call("run_regripper", {"hive_path": hive_path, "plugin": plugin}, analysis.regripper, hive_path, plugin)


@mcp.tool()
def run_log2timeline(image_path: str, output_path: str, partition_offset: str = "", parsers: str = "") -> str:
    """Generate a super timeline from a disk image using log2timeline/plaso. Output path must be within /tmp/sift-eye/."""
    args = {"image_path": image_path, "output_path": output_path, "partition_offset": partition_offset, "parsers": parsers}
    return _timed_call("run_log2timeline", args, analysis.log2timeline, image_path, output_path, partition_offset, parsers)


@mcp.tool()
def run_psort(plaso_file: str, output_path: str, time_range: str = "") -> str:
    """Convert plaso timeline to CSV. Optionally filter by time range (e.g., '2023-01-01..2023-12-31')."""
    args = {"plaso_file": plaso_file, "output_path": output_path, "time_range": time_range}
    return _timed_call("run_psort", args, analysis.psort, plaso_file, output_path, time_range)


@mcp.tool()
def run_exiftool(file_path: str) -> str:
    """Extract metadata from a file using ExifTool (images, documents, executables)."""
    return _timed_call("run_exiftool", {"file_path": file_path}, analysis.exiftool, file_path)


@mcp.tool()
def carve_files(image_path: str, output_dir: str, file_types: str = "") -> str:
    """Carve files from a disk image using foremost. Output directory must be within /tmp/sift-eye/. File types: 'jpg,pdf,exe' etc."""
    args = {"image_path": image_path, "output_dir": output_dir, "file_types": file_types}
    return _timed_call("carve_files", args, analysis.foremost, image_path, output_dir, file_types)


def main():
    """Run the MCP server over stdio."""
    import sys
    os.makedirs(CASE_DIR, exist_ok=True)
    print(f"[sift-eye-mcp] Case directory: {CASE_DIR}", file=sys.stderr)
    print(f"[sift-eye-mcp] Starting MCP server with {len(mcp._tool_manager._tools)} tools", file=sys.stderr)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
