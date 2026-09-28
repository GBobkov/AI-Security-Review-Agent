"""Run a project's pytest suite in a bounded subprocess."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any


TEST_TIMEOUT_SECONDS = 120
MAX_SUMMARY_CHARS = 20_000


def _summary(stdout: str | None, stderr: str | None) -> str:
    combined = "\n".join(part.strip() for part in (stdout, stderr) if part and part.strip())
    if not combined:
        return "pytest produced no output"
    if len(combined) > MAX_SUMMARY_CHARS:
        return "[output truncated]\n" + combined[-MAX_SUMMARY_CHARS:]
    return combined


def run_project_tests(root: Path) -> dict[str, Any]:
    """Run ``python -m pytest`` below *root* without invoking a shell."""

    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        return {
            "tests_status": "error",
            "summary": f"Project root is not a directory: {root}",
            "returncode": None,
        }

    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=TEST_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "tests_status": "error",
            "summary": f"pytest timed out after {TEST_TIMEOUT_SECONDS} seconds",
            "returncode": None,
        }
    except OSError as exc:
        return {
            "tests_status": "error",
            "summary": f"Could not start pytest: {exc}",
            "returncode": None,
        }

    return {
        "tests_status": "passed" if completed.returncode == 0 else "failed",
        "summary": _summary(completed.stdout, completed.stderr),
        "returncode": completed.returncode,
    }
