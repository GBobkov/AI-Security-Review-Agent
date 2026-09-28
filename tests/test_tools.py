from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from security_review.models import Finding, ReviewReport
from security_review import scanner, test_runner


def test_scan_project_maps_bandit_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = tmp_path / "unsafe.py"
    source.write_text("print('x')\n", encoding="utf-8")
    output = {
        "results": [
            {
                "test_id": "B602",
                "issue_severity": "high",
                "filename": str(source),
                "line_number": 7,
                "issue_text": "subprocess call with shell=True",
            }
        ]
    }

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command[:3] == [sys.executable, "-m", "bandit"]
        assert command[command.index("-t") + 1] == "B602,B608,B506"
        assert kwargs["shell"] is False
        return subprocess.CompletedProcess(command, 1, json.dumps(output), "")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    result = scanner.scan_project(tmp_path)

    assert result == {
        "scan_status": "ok",
        "findings": [
            {
                "issue": "B602",
                "severity": "HIGH",
                "file": "unsafe.py",
                "line": 7,
                "cwe": "CWE-78",
                "scanner_text": "subprocess call with shell=True",
            }
        ],
    }


def test_scan_project_reports_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_run(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("bandit", scanner.SCAN_TIMEOUT_SECONDS)

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    result = scanner.scan_project(tmp_path)
    assert result["scan_status"] == "error"
    assert result["findings"] == []
    assert "timed out" in result["error"]


def test_scan_project_reports_bandit_json_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    payload = {"results": [], "errors": [{"filename": "broken.py", "reason": "parse error"}]}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, json.dumps(payload), "")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    result = scanner.scan_project(tmp_path)
    assert result["scan_status"] == "error"
    assert result["findings"] == []
    assert "broken.py" in result["error"]


def test_run_project_tests_classifies_nonzero_as_failed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command == [sys.executable, "-m", "pytest"]
        assert kwargs["cwd"] == tmp_path.resolve()
        assert kwargs["shell"] is False
        return subprocess.CompletedProcess(command, 1, "1 failed", "")

    monkeypatch.setattr(test_runner.subprocess, "run", fake_run)
    result = test_runner.run_project_tests(tmp_path)
    assert result == {"tests_status": "failed", "summary": "1 failed", "returncode": 1}


def test_review_report_defaults() -> None:
    finding = Finding(
        issue="B608",
        severity="MEDIUM",
        file="app.py",
        line=3,
        cwe="CWE-89",
        explanation="SQL text is built dynamically.",
        suggested_fix="Use a parameterized query.",
        sources=["https://cwe.mitre.org/data/definitions/89.html"],
    )
    report = ReviewReport(scan_status="ok", findings=[finding])
    assert report.tests_status == "not_run"
    assert report.error is None


def test_mcp_read_file_and_rejects_symlink_escape(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pytest.importorskip("mcp")
    from security_review import mcp_server

    project = tmp_path / "project"
    project.mkdir()
    text_file = project / "notes.txt"
    text_file.write_text("first\nsecond\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (project / "escape.txt").symlink_to(outside)
    monkeypatch.setattr(mcp_server, "PROJECT_ROOT", project.resolve())

    assert mcp_server.read_file("notes.txt") == "1: first\n2: second"
    with pytest.raises(ValueError, match="outside"):
        mcp_server.read_file("escape.txt")


def test_mcp_run_tests_is_disabled_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("mcp")
    from security_review import mcp_server

    monkeypatch.delenv("SECURITY_REVIEW_ALLOW_TESTS", raising=False)
    result = mcp_server.run_tests()
    assert result["tests_status"] == "error"
    assert result["returncode"] is None
