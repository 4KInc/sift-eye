"""Evidence integrity verification — hash evidence files and detect tampering."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


HASH_ALGORITHM = "sha256"
BLOCK_SIZE = 65536  # 64 KB read blocks


def hash_file(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            block = f.read(BLOCK_SIZE)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def hash_evidence_files(evidence_paths: list[str], case_dir: str) -> dict:
    """Hash all evidence files and save to evidence_hashes.json.

    Returns dict mapping file path to hash.
    """
    case_path = Path(case_dir)
    case_path.mkdir(parents=True, exist_ok=True)

    hashes = {}
    for path in evidence_paths:
        p = Path(path)
        if not p.exists():
            hashes[str(p)] = {"error": "file not found"}
            continue
        if not p.is_file():
            hashes[str(p)] = {"error": "not a regular file"}
            continue

        file_hash = hash_file(str(p))
        hashes[str(p)] = {
            "hash": file_hash,
            "algorithm": HASH_ALGORITHM,
            "size_bytes": p.stat().st_size,
            "hashed_at": datetime.now(timezone.utc).isoformat(),
        }

    # Save to case directory
    hashes_file = case_path / "evidence_hashes.json"
    with open(hashes_file, "w") as f:
        json.dump(hashes, f, indent=2)

    return hashes


def verify_integrity(case_dir: str) -> dict:
    """Re-hash evidence files and compare against stored hashes.

    Returns verification result with pass/fail per file.
    """
    case_path = Path(case_dir)
    hashes_file = case_path / "evidence_hashes.json"

    if not hashes_file.exists():
        return {"status": "error", "message": "No evidence_hashes.json found. Run hash_evidence first."}

    with open(hashes_file) as f:
        stored = json.load(f)

    results = {}
    all_pass = True

    for file_path, info in stored.items():
        if "error" in info:
            results[file_path] = {"status": "skipped", "reason": info["error"]}
            continue

        p = Path(file_path)
        if not p.exists():
            results[file_path] = {"status": "FAIL", "reason": "file no longer exists"}
            all_pass = False
            continue

        current_hash = hash_file(file_path)
        if current_hash == info["hash"]:
            results[file_path] = {"status": "PASS", "hash": current_hash}
        else:
            results[file_path] = {
                "status": "FAIL",
                "expected": info["hash"],
                "actual": current_hash,
                "reason": "HASH MISMATCH — evidence may have been modified",
            }
            all_pass = False

    return {
        "status": "PASS" if all_pass else "FAIL",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "files": results,
    }
