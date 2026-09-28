"""Single-agent orchestration for local security reviews.

The scanner, file access, documentation search, and test runner are deliberately
reached through the local MCP server.  Ollama is used only for tool selection and
for turning the collected evidence into the project's structured ``Finding``
model.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import sys
from typing import Any, AsyncIterator

from .models import Finding, ReviewReport


DEFAULT_MODEL = "qwen3:4b"
MAX_FINDINGS = 3
MAX_TOOL_ROUNDS = 3

_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the source file containing the scanner finding.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_security_docs",
            "description": "Find local security guidance relevant to the finding.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
]


def _make_ollama_client() -> Any:
    from ollama import AsyncClient

    return AsyncClient()


@asynccontextmanager
async def _mcp_session(root: Path, allow_tests: bool) -> AsyncIterator[Any]:
    """Start the bundled MCP server with the reviewed project as its cwd."""

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    server = Path(__file__).with_name("mcp_server.py")
    source_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["SECURITY_REVIEW_PROJECT_ROOT"] = str(root)
    environment["SECURITY_REVIEW_ALLOW_TESTS"] = "1" if allow_tests else "0"
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(source_root)
        if not existing_pythonpath
        else os.pathsep.join((str(source_root), existing_pythonpath))
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(server)],
        cwd=str(root),
        env=environment,
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


def _as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump()
    return {}


def _message(response: Any) -> Any:
    if isinstance(response, dict):
        return response.get("message", {})
    return getattr(response, "message", {})


def _message_content(response: Any) -> str:
    message = _message(response)
    if isinstance(message, dict):
        return str(message.get("content", ""))
    return str(getattr(message, "content", ""))


def _tool_calls(response: Any) -> list[Any]:
    message = _message(response)
    if isinstance(message, dict):
        return list(message.get("tool_calls") or [])
    return list(getattr(message, "tool_calls", None) or [])


def _tool_call_parts(call: Any) -> tuple[str, dict[str, Any]]:
    raw = _as_mapping(call)
    function = raw.get("function", raw)
    function = _as_mapping(function)
    name = str(function.get("name", ""))
    arguments = function.get("arguments") or {}
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError:
            arguments = {}
    return name, arguments if isinstance(arguments, dict) else {}


def _assistant_message(response: Any) -> dict[str, Any]:
    message = _message(response)
    result = _as_mapping(message)
    if result:
        return result
    return {"role": "assistant", "content": _message_content(response)}


def _decode_mcp_result(result: Any) -> Any:
    """Accept both structured FastMCP results and JSON text MCP results."""

    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)
    if structured is not None:
        if isinstance(structured, dict) and set(structured) == {"result"}:
            return structured["result"]
        return structured

    content = getattr(result, "content", None)
    if content is None and isinstance(result, dict):
        content = result.get("content")
    if isinstance(content, list) and content:
        first = content[0]
        text = first.get("text") if isinstance(first, dict) else getattr(first, "text", None)
        if text is not None:
            try:
                return json.loads(text)
            except (json.JSONDecodeError, TypeError):
                return text
    return result


async def _call_mcp(session: Any, name: str, arguments: dict[str, Any]) -> Any:
    result = await session.call_tool(name, arguments)
    is_error = result.get("isError", False) if isinstance(result, dict) else getattr(result, "isError", False)
    decoded = _decode_mcp_result(result)
    if is_error:
        detail = decoded if isinstance(decoded, str) else json.dumps(decoded, ensure_ascii=False)
        raise RuntimeError(f"MCP tool {name!r} failed: {detail}")
    return decoded


def _evidence_prompt(raw: dict[str, Any]) -> str:
    return (
        "Investigate this static-analysis finding using both available tools. "
        "Call read_file for the finding's file and search_security_docs for its "
        "issue or CWE. Do not propose or apply a patch yet.\n\n"
        + json.dumps(raw, ensure_ascii=False)
    )


async def _collect_evidence(
    session: Any,
    ollama: Any,
    model: str,
    raw: dict[str, Any],
) -> tuple[list[dict[str, Any]], Any, Any]:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": "You are a careful local security reviewer."},
        {"role": "user", "content": _evidence_prompt(raw)},
    ]
    evidence: dict[str, Any] = {}

    for _ in range(MAX_TOOL_ROUNDS):
        response = await ollama.chat(model=model, messages=messages, tools=_TOOLS)
        messages.append(_assistant_message(response))
        for call in _tool_calls(response):
            name, arguments = _tool_call_parts(call)
            if name not in {"read_file", "search_security_docs"} or name in evidence:
                continue
            if name == "read_file":
                # Keep file access anchored to the scanner result.
                arguments = {"path": str(raw.get("file", ""))}
            else:
                requested_query = arguments.get("query") or raw.get("issue", "")
                # The local index's CWE filter is query driven, so always retain
                # the authoritative scanner CWE even when the model omits it.
                cwe = str(raw.get("cwe", ""))
                query = str(requested_query)
                if cwe and cwe.casefold() not in query.casefold():
                    query = f"{cwe} {query}".strip()
                arguments = {"query": query}
            evidence[name] = await _call_mcp(session, name, arguments)
            messages.append(
                {
                    "role": "tool",
                    "tool_name": name,
                    "content": json.dumps(evidence[name], ensure_ascii=False),
                }
            )
        if len(evidence) == 2:
            break
        missing = ", ".join(sorted({"read_file", "search_security_docs"} - evidence.keys()))
        messages.append({"role": "user", "content": f"You must still call: {missing}."})

    # Small local models occasionally fail to emit tool calls. Preserve the
    # evidence requirement with one bounded MCP fallback per missing tool.
    if "read_file" not in evidence:
        evidence["read_file"] = await _call_mcp(
            session, "read_file", {"path": str(raw.get("file", ""))}
        )
    if "search_security_docs" not in evidence:
        query = f"{raw.get('cwe', '')} {raw.get('issue', '')}".strip()
        evidence["search_security_docs"] = await _call_mcp(
            session, "search_security_docs", {"query": query}
        )
    return messages, evidence["read_file"], evidence["search_security_docs"]


def _doc_sources(docs: Any) -> list[str]:
    if isinstance(docs, dict):
        docs = docs.get("docs", docs.get("results", []))
    if not isinstance(docs, list):
        return []
    return [
        str(doc["source_url"])
        for doc in docs
        if isinstance(doc, dict) and doc.get("source_url")
    ]


async def _build_finding(
    ollama: Any,
    model: str,
    raw: dict[str, Any],
    source: Any,
    docs: Any,
) -> Finding:
    prompt = (
        "Return one concise security finding as JSON matching the supplied schema. "
        "Explain why the scanner result matters in this code and suggest a safe fix. "
        "Use only source URLs present in the documentation evidence. Do not claim a "
        "patch was applied.\n\nScanner result:\n"
        + json.dumps(raw, ensure_ascii=False)
        + "\n\nSource file:\n"
        + json.dumps(source, ensure_ascii=False)
        + "\n\nDocumentation:\n"
        + json.dumps(docs, ensure_ascii=False)
    )
    messages = [
        {"role": "system", "content": "You produce factual structured security reports."},
        {"role": "user", "content": prompt},
    ]
    validation_error: Exception | None = None
    values: dict[str, Any] | None = None
    for attempt in range(2):
        response = await ollama.chat(
            model=model,
            messages=messages,
            format=Finding.model_json_schema(),
            options={"temperature": 0},
        )
        try:
            generated = Finding.model_validate_json(_message_content(response))
            values = generated.model_dump()
            break
        except Exception as exc:
            validation_error = exc
            if attempt == 0:
                messages.append(
                    {
                        "role": "user",
                        "content": "Your response did not match the JSON schema. Return only one valid JSON object.",
                    }
                )
    if values is None:
        raise RuntimeError("Ollama did not return a valid structured finding after two attempts") from validation_error

    # Scanner-owned locations and classification are authoritative.
    values.update(
        {
            "issue": raw.get("issue"),
            "severity": raw.get("severity"),
            "file": raw.get("file"),
            "line": raw.get("line"),
            "cwe": raw.get("cwe"),
        }
    )
    allowed_sources = _doc_sources(docs)
    values["sources"] = [source for source in values.get("sources", []) if source in allowed_sources]
    if not values["sources"]:
        values["sources"] = allowed_sources
    return Finding.model_validate(values)


async def _review_project_async(
    root: Path,
    run_tests: bool,
    max_findings: int,
) -> ReviewReport:
    root = root.expanduser().resolve()
    if not root.is_dir():
        return ReviewReport(
            scan_status="error",
            findings=[],
            tests_status="not_run",
            error=f"Project directory does not exist: {root}",
        )

    limit = max(1, min(int(max_findings), MAX_FINDINGS))
    model = os.environ.get("SECURITY_REVIEW_MODEL", os.environ.get("OLLAMA_MODEL", DEFAULT_MODEL))
    ollama = _make_ollama_client()

    try:
        async with _mcp_session(root, run_tests) as session:
            scan = await _call_mcp(session, "run_security_scan", {})
            if not isinstance(scan, dict) or scan.get("scan_status") != "ok":
                error = scan.get("error") if isinstance(scan, dict) else str(scan)
                return ReviewReport(
                    scan_status="error",
                    findings=[],
                    tests_status="not_run",
                    error=error or "Security scan failed",
                )

            findings: list[Finding] = []
            for raw in list(scan.get("findings") or [])[:limit]:
                if not isinstance(raw, dict):
                    continue
                _, source, docs = await _collect_evidence(session, ollama, model, raw)
                findings.append(await _build_finding(ollama, model, raw, source, docs))

            tests_status = "not_run"
            if run_tests:
                test_result = await _call_mcp(session, "run_tests", {})
                if isinstance(test_result, dict):
                    tests_status = str(test_result.get("status", test_result.get("tests_status", "error")))
                else:
                    tests_status = "error"
                if tests_status not in {"passed", "failed", "error"}:
                    tests_status = "error"

            return ReviewReport(
                scan_status="ok",
                findings=findings,
                tests_status=tests_status,
                error=None,
            )
    except Exception as exc:
        return ReviewReport(
            scan_status="error",
            findings=[],
            tests_status="not_run",
            error=str(exc),
        )


def review_project(
    root: Path,
    run_tests: bool = False,
    max_findings: int = 3,
) -> ReviewReport:
    """Review a local project and return a validated structured report."""

    return asyncio.run(_review_project_async(Path(root), run_tests, max_findings))
