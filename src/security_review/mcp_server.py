"""MCP stdio server exposing the review agent's local, bounded tools."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from security_review.scanner import scan_project
from security_review.test_runner import run_project_tests


MAX_FILE_BYTES = 100_000
PROJECT_ROOT = Path(os.environ.get("SECURITY_REVIEW_PROJECT_ROOT", os.getcwd())).expanduser().resolve()

mcp = FastMCP("security-review")


def _project_path(path: str) -> Path:
    requested = Path(path).expanduser()
    candidate = requested if requested.is_absolute() else PROJECT_ROOT / requested
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(PROJECT_ROOT)
    except FileNotFoundError as exc:
        raise ValueError(f"File does not exist: {path}") from exc
    except ValueError as exc:
        raise ValueError("Path is outside the configured project root") from exc
    if not resolved.is_file():
        raise ValueError(f"Path is not a file: {path}")
    return resolved


@mcp.tool()
def read_file(path: str) -> str:
    """Read a UTF-8 text file inside the project, with numbered lines."""

    target = _project_path(path)
    size = target.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"File is too large ({size} bytes; limit is {MAX_FILE_BYTES})")
    try:
        text = target.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("File is not UTF-8 text") from exc
    return "\n".join(f"{number}: {line}" for number, line in enumerate(text.splitlines(), 1))


@mcp.tool()
def run_security_scan() -> dict[str, Any]:
    """Run the bounded Bandit security scan on the configured project."""

    return scan_project(PROJECT_ROOT)


@mcp.tool()
def search_security_docs(query: str) -> list[dict[str, Any]]:
    """Search the bundled security guidance for a query."""

    if not query.strip():
        raise ValueError("query must not be empty")
    from security_review.rag import search_docs

    return search_docs(query)


@mcp.tool()
def run_tests() -> dict[str, Any]:
    """Run project tests when explicitly enabled by the host environment."""

    if os.environ.get("SECURITY_REVIEW_ALLOW_TESTS") != "1":
        return {
            "tests_status": "error",
            "summary": "Test execution is disabled; set SECURITY_REVIEW_ALLOW_TESTS=1 to enable it",
            "returncode": None,
        }
    return run_project_tests(PROJECT_ROOT)


def main() -> None:
    """Start the MCP server over stdio."""

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
