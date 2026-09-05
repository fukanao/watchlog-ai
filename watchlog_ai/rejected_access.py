from dataclasses import replace
from pathlib import Path

from .ai import AnalysisResult
from .severity import Severity


def is_rejected_access(source_name: str) -> bool:
    name = source_name.rsplit(" part ", 1)
    if len(name) == 2 and name[1].isdigit():
        source_name = name[0]
    return Path(source_name).name in {"znw-support-ai-rejected-access.log", "rejected-access.log"}


def apply_source_policy(result: AnalysisResult, source_name: str) -> AnalysisResult:
    blocked = is_rejected_access(source_name)
    incidents = [
        replace(item, source_names=[source_name],
                severity=Severity.LOW if blocked and item.severity != Severity.NONE else item.severity)
        for item in result.incidents
    ]
    severity = max([result.severity, *(item.severity for item in incidents)], key=lambda value: value.score)
    if blocked and severity != Severity.NONE:
        severity = Severity.LOW
    return replace(result, severity=severity, incidents=incidents, source_names=[source_name])


def should_report(result: AnalysisResult) -> bool:
    return result.severity.should_notify or (
        result.severity == Severity.LOW and any(is_rejected_access(name) for name in result.source_names)
    )


def report_label(severity: Severity, source_names: list[str]) -> str:
    if severity == Severity.LOW and any(is_rejected_access(name) for name in source_names):
        return "小"
    return severity.label_ja
