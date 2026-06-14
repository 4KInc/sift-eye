"""Analysis tools — hashing, strings, yara, regripper, timeline. All read-only."""

import hashlib
import subprocess
from pathlib import Path


def _run(cmd: list[str], timeout: int = 120) -> str:
    """Run a command and return stdout."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout
        if result.returncode != 0 and result.stderr:
            output += f"\n[STDERR]: {result.stderr}"
        return output
    except subprocess.TimeoutExpired:
        return f"[ERROR] Command timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return f"[ERROR] Command not found: {cmd[0]}. Is it installed on the SIFT Workstation?"


def _is_safe_output_path(path: str) -> bool:
    """Ensure output path is within /tmp/sift-eye/."""
    resolved = str(Path(path).resolve())
    return resolved.startswith("/tmp/sift-eye/")


def hash_file(file_path: str, algorithm: str = "sha256") -> str:
    """Compute hash of a file (sha256, md5, sha1).

    Args:
        file_path: Path to the file to hash
        algorithm: Hash algorithm (sha256, md5, sha1)
    """
    algos = {"sha256": hashlib.sha256, "md5": hashlib.md5, "sha1": hashlib.sha1}
    if algorithm not in algos:
        return f"[ERROR] Unsupported algorithm: {algorithm}. Use sha256, md5, or sha1."

    h = algos[algorithm]()
    try:
        with open(file_path, "rb") as f:
            while True:
                block = f.read(65536)
                if not block:
                    break
                h.update(block)
        return f"{algorithm}:{h.hexdigest()}  {file_path}"
    except FileNotFoundError:
        return f"[ERROR] File not found: {file_path}"
    except PermissionError:
        return f"[ERROR] Permission denied: {file_path}"


def strings_search(file_path: str, min_length: int = 4, encoding: str = "auto", grep: str = "") -> str:
    """Extract strings from a file (binary or text).

    Args:
        file_path: Path to the file
        min_length: Minimum string length (default 4)
        encoding: String encoding — 'ascii', 'unicode', or 'auto' (both)
        grep: If provided, filter strings matching this pattern
    """
    results = []

    if encoding in ("ascii", "auto"):
        cmd = ["strings", f"-n{min_length}", file_path]
        if grep:
            output = _run(cmd, timeout=120)
            lines = [l for l in output.splitlines() if grep.lower() in l.lower()]
            results.append(f"[ASCII strings matching '{grep}'] ({len(lines)} matches):")
            results.extend(lines[:500])
        else:
            output = _run(cmd, timeout=120)
            lines = output.splitlines()
            results.append(f"[ASCII strings] ({len(lines)} total, showing first 500):")
            results.extend(lines[:500])

    if encoding in ("unicode", "auto"):
        cmd = ["strings", f"-n{min_length}", "-el", file_path]
        if grep:
            output = _run(cmd, timeout=120)
            lines = [l for l in output.splitlines() if grep.lower() in l.lower()]
            results.append(f"\n[Unicode strings matching '{grep}'] ({len(lines)} matches):")
            results.extend(lines[:500])
        else:
            output = _run(cmd, timeout=120)
            lines = output.splitlines()
            results.append(f"\n[Unicode strings] ({len(lines)} total, showing first 500):")
            results.extend(lines[:500])

    return "\n".join(results)


def yara_scan(rules_path: str, target_path: str) -> str:
    """Scan a file or directory with YARA rules.

    Args:
        rules_path: Path to YARA rules file
        target_path: File or directory to scan
    """
    return _run(["yara", "-r", rules_path, target_path], timeout=300)


def regripper(hive_path: str, plugin: str = "") -> str:
    """Run RegRipper against a Windows registry hive.

    Args:
        hive_path: Path to the registry hive file (SAM, SYSTEM, SOFTWARE, NTUSER.DAT, etc.)
        plugin: Specific RegRipper plugin to run (default: run all applicable plugins)
    """
    cmd = ["rip.pl", "-r", hive_path]
    if plugin:
        cmd.extend(["-p", plugin])
    else:
        cmd.extend(["-a"])  # Run all plugins
    return _run(cmd, timeout=300)


def log2timeline(image_path: str, output_path: str, partition_offset: str = "", parsers: str = "") -> str:
    """Generate a super timeline from a disk image using log2timeline/plaso.

    Args:
        image_path: Path to the disk image
        output_path: Path for the plaso storage file (must be in /tmp/sift-eye/)
        partition_offset: Partition offset in sectors
        parsers: Comma-separated list of parsers (default: all)
    """
    if not _is_safe_output_path(output_path):
        return "[ERROR] Output path must be within /tmp/sift-eye/ for evidence integrity."

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    cmd = ["log2timeline.py", "--status_view", "none", "--logfile", "/dev/null"]
    if partition_offset:
        cmd.extend(["--partition_offset", partition_offset])
    if parsers:
        cmd.extend(["--parsers", parsers])
    cmd.extend([output_path, image_path])

    return _run(cmd, timeout=3600)  # Can take a long time


def psort(plaso_file: str, output_path: str, time_range: str = "") -> str:
    """Sort and filter a plaso timeline file, output as CSV.

    Args:
        plaso_file: Path to the plaso storage file
        output_path: Path for the CSV output (must be in /tmp/sift-eye/)
        time_range: Time range filter (e.g., '2023-01-01..2023-12-31')
    """
    if not _is_safe_output_path(output_path):
        return "[ERROR] Output path must be within /tmp/sift-eye/ for evidence integrity."

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    cmd = ["psort.py", "-o", "l2tcsv", "-w", output_path]
    if time_range:
        cmd.extend(["--slice", time_range])
    cmd.append(plaso_file)

    return _run(cmd, timeout=1800)


def exiftool(file_path: str) -> str:
    """Extract metadata from a file using ExifTool (images, documents, executables)."""
    return _run(["exiftool", file_path], timeout=30)


def foremost(image_path: str, output_dir: str, file_types: str = "") -> str:
    """Carve files from a disk image using foremost.

    Args:
        image_path: Path to the disk image or raw partition
        output_dir: Output directory (must be in /tmp/sift-eye/)
        file_types: Comma-separated file types to carve (e.g., 'jpg,pdf,exe')
    """
    if not _is_safe_output_path(output_dir):
        return "[ERROR] Output directory must be within /tmp/sift-eye/ for evidence integrity."

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    cmd = ["foremost", "-o", output_dir, "-i", image_path]
    if file_types:
        cmd.extend(["-t", file_types])

    return _run(cmd, timeout=600)
