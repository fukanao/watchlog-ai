from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

    @classmethod
    def parse(cls, value: object) -> "Severity":
        normalized = str(value or "").strip().lower()
        mapping = {
            "高": cls.HIGH,
            "high": cls.HIGH,
            "critical": cls.HIGH,
            "中": cls.MEDIUM,
            "medium": cls.MEDIUM,
            "warning": cls.MEDIUM,
            "低": cls.LOW,
            "low": cls.LOW,
            "無": cls.NONE,
            "なし": cls.NONE,
            "none": cls.NONE,
            "normal": cls.NONE,
        }
        return mapping.get(normalized, cls.NONE)

    @property
    def label_ja(self) -> str:
        return {
            Severity.HIGH: "高",
            Severity.MEDIUM: "中",
            Severity.LOW: "低",
            Severity.NONE: "無",
        }[self]

    @property
    def score(self) -> int:
        return {
            Severity.NONE: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
        }[self]

    @property
    def should_notify(self) -> bool:
        return self.score >= Severity.MEDIUM.score


def max_severity(*values: Severity) -> Severity:
    return max(values, key=lambda item: item.score, default=Severity.NONE)
