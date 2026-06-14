"""Memory forensic tools — Volatility 3 wrappers. All read-only."""

import subprocess


def _run_vol(plugin: str, memory_path: str, extra_args: list[str] | None = None, timeout: int = 300) -> str:
    """Run a Volatility 3 plugin against a memory dump."""
    cmd = ["vol", "-f", memory_path, plugin]
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout
        if result.returncode != 0 and result.stderr:
            # Volatility often writes progress to stderr
            stderr_lines = [l for l in result.stderr.splitlines() if not l.startswith("Volatility 3") and "Progress:" not in l]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"
        return output
    except subprocess.TimeoutExpired:
        return f"[ERROR] Volatility plugin {plugin} timed out after {timeout}s"
    except FileNotFoundError:
        return "[ERROR] vol (Volatility 3) not found. Is it installed on the SIFT Workstation?"


def vol_pslist(memory_path: str) -> str:
    """List running processes from memory dump (PID, PPID, name, create time, exit time)."""
    return _run_vol("windows.pslist.PsList", memory_path)


def vol_pstree(memory_path: str) -> str:
    """Show process tree from memory dump (parent-child relationships)."""
    return _run_vol("windows.pstree.PsTree", memory_path)


def vol_netscan(memory_path: str) -> str:
    """Scan for network connections and listening sockets in memory."""
    return _run_vol("windows.netscan.NetScan", memory_path)


def vol_cmdline(memory_path: str) -> str:
    """Show command-line arguments for each process in memory."""
    return _run_vol("windows.cmdline.CmdLine", memory_path)


def vol_malfind(memory_path: str) -> str:
    """Detect injected code and suspicious memory regions (PE headers in non-image sections)."""
    return _run_vol("windows.malfind.Malfind", memory_path)


def vol_dlllist(memory_path: str, pid: int | None = None) -> str:
    """List loaded DLLs for each process (or a specific PID)."""
    extra = ["--pid", str(pid)] if pid else None
    return _run_vol("windows.dlllist.DllList", memory_path, extra)


def vol_filescan(memory_path: str) -> str:
    """Scan for file objects in memory (finds open files, mapped files, etc.)."""
    return _run_vol("windows.filescan.FileScan", memory_path, timeout=600)


def vol_handles(memory_path: str, pid: int | None = None) -> str:
    """List open handles for processes (files, registry keys, mutexes, etc.)."""
    extra = ["--pid", str(pid)] if pid else None
    return _run_vol("windows.handles.Handles", memory_path, extra, timeout=600)


def vol_hivelist(memory_path: str) -> str:
    """List registry hives found in memory."""
    return _run_vol("windows.registry.hivelist.HiveList", memory_path)


def vol_printkey(memory_path: str, key: str) -> str:
    """Print a specific registry key and its values from memory."""
    return _run_vol("windows.registry.printkey.PrintKey", memory_path, ["--key", key])


def vol_hashdump(memory_path: str) -> str:
    """Extract password hashes from memory (SAM + SYSTEM hives)."""
    return _run_vol("windows.hashdump.Hashdump", memory_path)


def vol_envars(memory_path: str, pid: int | None = None) -> str:
    """Display environment variables for processes."""
    extra = ["--pid", str(pid)] if pid else None
    return _run_vol("windows.envars.Envars", memory_path, extra)


def vol_svcscan(memory_path: str) -> str:
    """Scan for Windows services in memory."""
    return _run_vol("windows.svcscan.SvcScan", memory_path)
