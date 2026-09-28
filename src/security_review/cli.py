"""Command-line entry point for local security reviews."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .agent import MAX_FINDINGS, review_project


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Review a local project with Ollama and MCP")
    parser.add_argument("target", type=Path, help="project directory to review")
    parser.add_argument("--run-tests", action="store_true", help="run project tests through MCP")
    parser.add_argument(
        "--max-findings",
        type=int,
        default=3,
        metavar="N",
        help=f"maximum findings to enrich (1-{MAX_FINDINGS}, default: 3)",
    )
    parser.add_argument("--output", type=Path, help="write JSON report to this file")
    parser.add_argument(
        "--build-index",
        action="store_true",
        help="rebuild the local security-document index before reviewing",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.max_findings < 1 or args.max_findings > MAX_FINDINGS:
        raise SystemExit(f"--max-findings must be between 1 and {MAX_FINDINGS}")

    if args.build_index:
        from .rag import build_index

        index_path = build_index()
        print(f"Built security knowledge index: {index_path}", file=sys.stderr)

    report = review_project(args.target, args.run_tests, args.max_findings)
    payload = report.model_dump_json(indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0 if report.scan_status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
