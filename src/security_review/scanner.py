"""Small, deterministic wrapper around Bandit's JSON output."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


CHECKS = ("B602", "B608", "B506")
CWE_BY_TEST = {
    "B602": "CWE-78",
    "B608": "CWE-89",
    "B506": "CWE-502",
}
EXCLUDED_DIRECTORIES = (".git", ".venv", "venv", "node_modules", "__pycache__")
SCAN_TIMEOUT_SECONDS = 60


def _error(message: str) -> dict[str, Any]:
    return {"scan_status": "error", "findings": [], "error": message}


def _relative_filename(filename: object, root: Path) -> str:
    candidate = Path(str(filename))
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        return candidate.resolve(strict=False).relative_to(root).as_posix()
    except ValueError:
        # Bandit normally emits paths below the scanned root. Do not expose an
        # absolute path if a malformed/unexpected result says otherwise.
        return Path(str(filename)).name


def scan_project(root: Path) -> dict[str, Any]:
    """Scan *root* for the three security checks used by this project.

    Bandit exits with status 1 when it found issues, so both 0 and 1 are valid
    result-producing statuses.
    """

    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        return _error(f"Project root is not a directory: {root}")

    excluded = ",".join(str(root / name) for name in EXCLUDED_DIRECTORIES)
    command = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(root),
        "-f",
        "json",
        "-t",
        ",".join(CHECKS),
        "-x",
        excluded,
    ]

    try:
        completed = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return _error(f"Bandit scan timed out after {SCAN_TIMEOUT_SECONDS} seconds")
    except OSError as exc:
        return _error(f"Could not start Bandit: {exc}")

    if completed.returncode not in (0, 1):
        detail = (completed.stderr or completed.stdout).strip()
        message = f"Bandit exited with status {completed.returncode}"
        return _error(f"{message}: {detail}" if detail else message)

    try:
        payload = json.loads(completed.stdout or "{}")
    except (json.JSONDecodeError, TypeError) as exc:
        return _error(f"Bandit returned invalid JSON: {exc}")

    results = payload.get("results", [])
    if not isinstance(results, list):
        return _error("Bandit JSON did not contain a results list")

    findings: list[dict[str, Any]] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        test_id = str(item.get("test_id", ""))
        if test_id not in CWE_BY_TEST:
            continue
        try:
            line = int(item.get("line_number", 0))
        except (TypeError, ValueError):
            line = 0
        findings.append(
            {
                "issue": test_id,
                "severity": str(item.get("issue_severity", "UNKNOWN")).upper(),
                "file": _relative_filename(item.get("filename", ""), root),
                "line": line,
                "cwe": CWE_BY_TEST[test_id],
                "scanner_text": str(item.get("issue_text", "")),
            }
        )

    scan_errors = payload.get("errors", [])
    if scan_errors:
        try:
            detail = json.dumps(scan_errors, ensure_ascii=False)
        except (TypeError, ValueError):
            detail = str(scan_errors)
        return {
            "scan_status": "error",
            "findings": findings,
            "error": f"Bandit reported scan errors: {detail}",
        }

    return {"scan_status": "ok", "findings": findings}
