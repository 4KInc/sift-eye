"""Structured audit logging for every MCP tool invocation."""

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    """Logs every tool call to audit_log.jsonl with timestamp, tool, args, output hash, duration."""

    def __init__(self, case_dir: str):
        self.case_dir = Path(case_dir)
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.case_dir / "audit_log.jsonl"
        self._sequence = 0

    def log_tool_call(
        self,
        tool_name: str,
        arguments: dict,
        output: str,
        duration_ms: float,
        success: bool,
        error: str | None = None,
    ) -> dict:
        """Log a single tool invocation and return the log entry."""
        self._sequence += 1
        output_hash = hashlib.sha256(output.encode()).hexdigest()

        entry = {
            "sequence": self._sequence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool_name,
            "arguments": _sanitize_args(arguments),
            "output_hash": output_hash,
            "output_bytes": len(output.encode()),
            "duration_ms": round(duration_ms, 2),
            "success": success,
        }
        if error:
            entry["error"] = error

        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        return entry

    def get_stats(self) -> dict:
        """Return summary statistics of tool usage."""
        if not self.log_path.exists():
            return {"total_calls": 0, "tools_used": []}

        tools = {}
        total = 0
        total_duration = 0.0
        errors = 0

        with open(self.log_path) as f:
            for line in f:
                entry = json.loads(line)
                total += 1
                total_duration += entry.get("duration_ms", 0)
                tool = entry["tool"]
                tools[tool] = tools.get(tool, 0) + 1
                if not entry.get("success", True):
                    errors += 1

        return {
            "total_calls": total,
            "total_duration_ms": round(total_duration, 2),
            "errors": errors,
            "tools_used": sorted(tools.items(), key=lambda x: -x[1]),
        }


def _sanitize_args(args: dict) -> dict:
    """Remove excessively large values from args for logging."""
    sanitized = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > 1000:
            sanitized[k] = v[:500] + f"... ({len(v)} chars)"
        else:
            sanitized[k] = v
    return sanitized
