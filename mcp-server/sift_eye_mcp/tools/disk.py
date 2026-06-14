"""Disk forensic tools — Sleuthkit + ewftools wrappers. All read-only."""

import subprocess
from pathlib import Path


def _run(cmd: list[str], timeout: int = 120) -> str:
    """Run a command and return stdout. Raises on timeout."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout
        if result.returncode != 0 and result.stderr:
            output += f"\n[STDERR]: {result.stderr}"
        return output
    except subprocess.TimeoutExpired:
        return f"[ERROR] Command timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return f"[ERROR] Command not found: {cmd[0]}. Is it installed on the SIFT Workstation?"


def ewfinfo(image_path: str) -> str:
    """Get metadata from an E01/EWF forensic image (case number, examiner, media size, hash)."""
    return _run(["ewfinfo", image_path])


def mmls(image_path: str) -> str:
    """Display partition layout of a disk image. Shows partition table, offsets, sizes."""
    return _run(["mmls", image_path])


def fls(
    image_path: str,
    inode: str = "",
    partition_offset: str = "",
    recursive: bool = False,
    deleted_only: bool = False,
    long_format: bool = True,
) -> str:
    """List files and directories in a disk image (like ls for forensic images).

    Args:
        image_path: Path to the disk image (E01, raw, etc.)
        inode: Inode number to list (default: root directory)
        partition_offset: Partition offset in sectors (from mmls output)
        recursive: If True, list recursively
        deleted_only: If True, only show deleted files
        long_format: If True, show timestamps and sizes
    """
    cmd = ["fls"]
    if partition_offset:
        cmd.extend(["-o", partition_offset])
    if recursive:
        cmd.append("-r")
    if deleted_only:
        cmd.append("-d")
    if long_format:
        cmd.append("-l")
    cmd.append(image_path)
    if inode:
        cmd.append(inode)
    return _run(cmd, timeout=300)


def icat(image_path: str, inode: str, partition_offset: str = "", output_path: str = "") -> str:
    """Extract a file from a disk image by inode number.

    Args:
        image_path: Path to the disk image
        inode: Inode number of the file to extract
        partition_offset: Partition offset in sectors
        output_path: Where to write the extracted file (must be in case output dir)
    """
    if output_path and not _is_safe_output_path(output_path):
        return "[ERROR] Output path must be within /tmp/sift-eye/ for evidence integrity."

    cmd = ["icat"]
    if partition_offset:
        cmd.extend(["-o", partition_offset])
    cmd.extend([image_path, inode])

    if output_path:
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=120)
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(result.stdout)
            return f"Extracted {len(result.stdout)} bytes to {output_path}"
        except subprocess.TimeoutExpired:
            return f"[ERROR] Extraction timed out for inode {inode}"
    else:
        # Return first 4096 bytes as hex + ASCII for inspection
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=120)
            data = result.stdout[:4096]
            # Try text first
            try:
                text = data.decode("utf-8", errors="replace")
                return f"[First 4096 bytes as text]:\n{text}"
            except Exception:
                return f"[Binary data, {len(result.stdout)} bytes total, showing first 256 hex]:\n{data[:256].hex()}"
        except subprocess.TimeoutExpired:
            return f"[ERROR] Read timed out for inode {inode}"


def file_type(image_path: str, inode: str, partition_offset: str = "") -> str:
    """Determine the file type of a file in a disk image by inode (using icat | file -)."""
    cmd_icat = ["icat"]
    if partition_offset:
        cmd_icat.extend(["-o", partition_offset])
    cmd_icat.extend([image_path, inode])

    try:
        p1 = subprocess.Popen(cmd_icat, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p2 = subprocess.Popen(["file", "-"], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p1.stdout.close()
        output, _ = p2.communicate(timeout=30)
        return output.decode().strip()
    except subprocess.TimeoutExpired:
        return "[ERROR] file type detection timed out"
    except FileNotFoundError:
        return "[ERROR] file command not found"


def tsk_recover(
    image_path: str,
    output_dir: str,
    partition_offset: str = "",
    file_type_filter: str = "",
) -> str:
    """Recover deleted files from a disk image to the output directory.

    Args:
        image_path: Path to the disk image
        output_dir: Where to write recovered files (must be in /tmp/sift-eye/)
        partition_offset: Partition offset in sectors
        file_type_filter: File extension filter (e.g., 'exe', 'pdf')
    """
    if not _is_safe_output_path(output_dir):
        return "[ERROR] Output directory must be within /tmp/sift-eye/ for evidence integrity."

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    cmd = ["tsk_recover"]
    if partition_offset:
        cmd.extend(["-o", partition_offset])
    cmd.extend(["-e", image_path, output_dir])

    return _run(cmd, timeout=600)


def fsstat(image_path: str, partition_offset: str = "") -> str:
    """Display filesystem details (type, block size, volume label, etc.)."""
    cmd = ["fsstat"]
    if partition_offset:
        cmd.extend(["-o", partition_offset])
    cmd.append(image_path)
    return _run(cmd, timeout=60)


def ifind(image_path: str, file_path: str, partition_offset: str = "") -> str:
    """Find the inode for a given file path in the image."""
    cmd = ["ifind", "-n", file_path]
    if partition_offset:
        cmd.extend(["-o", partition_offset])
    cmd.append(image_path)
    return _run(cmd, timeout=30)


def blkstat(image_path: str, block_number: str, partition_offset: str = "") -> str:
    """Display details about a specific disk block/cluster."""
    cmd = ["blkstat"]
    if partition_offset:
        cmd.extend(["-o", partition_offset])
    cmd.extend([image_path, block_number])
    return _run(cmd, timeout=30)


def _is_safe_output_path(path: str) -> bool:
    """Ensure output path is within /tmp/sift-eye/ to protect evidence."""
    resolved = str(Path(path).resolve())
    return resolved.startswith("/tmp/sift-eye/")
