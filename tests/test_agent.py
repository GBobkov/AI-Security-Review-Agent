from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_review import agent


class FakeSession:
    def __init__(self, scan, test_result=None):
        self.scan = scan
        self.test_result = test_result or {"tests_status": "passed"}
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if name == "run_security_scan":
            return self.scan
        if name == "read_file":
            return "1: import subprocess\n2: subprocess.run(user_input, shell=True)"
        if name == "search_security_docs":
            return [
                {
                    "title": "OS command injection",
                    "cwe": "CWE-78",
                    "source_url": "https://cwe.mitre.org/data/definitions/78.html",
                    "text": "Avoid invoking a shell with untrusted input.",
                    "score": 0.9,
                }
            ]
        if name == "run_tests":
            return self.test_result
        raise AssertionError(name)


class FakeOllama:
    def __init__(self):
        self.calls = []

    async def chat(self, **kwargs):
        self.calls.append(kwargs)
        if "format" in kwargs:
            return {
                "message": {
                    "content": json.dumps(
                        {
                            "issue": "invented issue",
                            "severity": "LOW",
                            "file": "wrong.py",
                            "line": 999,
                            "cwe": "CWE-999",
                            "explanation": "Untrusted input reaches a shell.",
                            "suggested_fix": "Use an argument list and disable shell execution.",
                            "sources": [
                                "https://cwe.mitre.org/data/definitions/78.html",
                                "https://example.invalid/hallucinated",
                            ],
                        }
                    )
                }
            }
        return {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"function": {"name": "read_file", "arguments": {"path": "wrong.py"}}},
                    {
                        "function": {
                            "name": "search_security_docs",
                            "arguments": {"query": "CWE-78 command injection"},
                        }
                    },
                ],
            }
        }


def _scan(count=1):
    return {
        "scan_status": "ok",
        "findings": [
            {
                "issue": f"shell injection {number}",
                "severity": "HIGH",
                "file": f"app{number}.py",
                "line": number + 10,
                "cwe": "CWE-78",
                "scanner_text": "subprocess call with shell=True",
            }
            for number in range(count)
        ],
    }


def _install_fakes(monkeypatch, session, ollama):
    @asynccontextmanager
    async def fake_mcp_session(root, allow_tests):
        yield session

    monkeypatch.setattr(agent, "_mcp_session", fake_mcp_session)
    monkeypatch.setattr(agent, "_make_ollama_client", lambda: ollama)


def test_review_enriches_bounded_findings_and_preserves_scanner_facts(tmp_path, monkeypatch):
    session = FakeSession(_scan(count=3))
    ollama = FakeOllama()
    _install_fakes(monkeypatch, session, ollama)

    report = agent.review_project(tmp_path, max_findings=1)

    assert report.scan_status == "ok"
    assert report.tests_status == "not_run"
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert (finding.issue, finding.severity, finding.file, finding.line, finding.cwe) == (
        "shell injection 0",
        "HIGH",
        "app0.py",
        10,
        "CWE-78",
    )
    assert finding.sources == ["https://cwe.mitre.org/data/definitions/78.html"]
    assert session.calls == [
        ("run_security_scan", {}),
        ("read_file", {"path": "app0.py"}),
        ("search_security_docs", {"query": "CWE-78 command injection"}),
    ]
    assert len(ollama.calls) == 2
    assert "format" not in ollama.calls[0]
    assert ollama.calls[1]["format"] == agent.Finding.model_json_schema()


def test_run_tests_is_only_called_when_enabled(tmp_path, monkeypatch):
    session = FakeSession(_scan(count=0), {"tests_status": "failed"})
    _install_fakes(monkeypatch, session, FakeOllama())

    without_tests = agent.review_project(tmp_path)
    assert without_tests.tests_status == "not_run"
    assert [name for name, _ in session.calls] == ["run_security_scan"]

    session.calls.clear()
    with_tests = agent.review_project(tmp_path, run_tests=True)
    assert with_tests.tests_status == "failed"
    assert [name for name, _ in session.calls] == ["run_security_scan", "run_tests"]


def test_missing_llm_tool_calls_use_one_bounded_fallback_each(tmp_path, monkeypatch):
    class NoToolsOllama(FakeOllama):
        async def chat(self, **kwargs):
            if "format" in kwargs:
                return await super().chat(**kwargs)
            self.calls.append(kwargs)
            return {"message": {"role": "assistant", "content": "No tools"}}

    session = FakeSession(_scan())
    ollama = NoToolsOllama()
    _install_fakes(monkeypatch, session, ollama)

    report = agent.review_project(tmp_path)

    assert report.scan_status == "ok"
    assert [name for name, _ in session.calls].count("read_file") == 1
    assert [name for name, _ in session.calls].count("search_security_docs") == 1
    tool_rounds = [call for call in ollama.calls if "tools" in call]
    assert len(tool_rounds) == agent.MAX_TOOL_ROUNDS


def test_real_mcp_stdio_server_smoke():
    project = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_app"

    async def exercise_server():
        async with agent._mcp_session(project, False) as session:
            scan = await agent._call_mcp(session, "run_security_scan", {})
            source = await agent._call_mcp(session, "read_file", {"path": "app.py"})
            return scan, source

    scan, source = asyncio.run(exercise_server())

    assert scan["scan_status"] == "ok"
    assert scan["findings"]
    assert "subprocess" in source


def test_mcp_tool_error_is_raised_with_tool_name_and_message():
    class ErrorSession:
        async def call_tool(self, name, arguments):
            return SimpleNamespace(
                isError=True,
                structuredContent=None,
                content=[SimpleNamespace(text="security knowledge index is missing")],
            )

    with pytest.raises(
        RuntimeError,
        match="search_security_docs.*security knowledge index is missing",
    ):
        asyncio.run(agent._call_mcp(ErrorSession(), "search_security_docs", {"query": "CWE-78"}))
