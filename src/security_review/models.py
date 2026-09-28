"""Pydantic models shared by the security review agent."""

from typing import Literal

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """A scanner finding enriched with an explanation and remediation advice."""

    issue: str
    severity: str
    file: str
    line: int
    cwe: str
    explanation: str
    suggested_fix: str
    sources: list[str] = Field(default_factory=list)


class ReviewReport(BaseModel):
    """Final result returned by the review agent."""

    scan_status: Literal["ok", "error"]
    findings: list[Finding] = Field(default_factory=list)
    tests_status: Literal["not_run", "passed", "failed", "error"] = "not_run"
    error: str | None = None
