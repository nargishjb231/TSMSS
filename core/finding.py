"""Finding model with mandatory evidence and confidence semantics."""
from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from config import SEVERITY_ORDER

CRITICAL, HIGH, MEDIUM, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
CONFIRMED = "CONFIRMED"
HIGH_CONF = "HIGH CONFIDENCE"
MED_CONF = "MEDIUM CONFIDENCE"
LOW_CONF = "LOW CONFIDENCE"
NEEDS_MANUAL = "NEEDS MANUAL VERIFICATION"
HEURISTIC = "HEURISTIC"
MANUAL = "MANUAL REVIEW"

_CONF_RANK = {CONFIRMED: 5, HIGH_CONF: 4, MED_CONF: 3, LOW_CONF: 2,
             NEEDS_MANUAL: 1, HEURISTIC: 1, MANUAL: 1}

# Checks that may only ever be CONFIRMED because they assert a positive fact.
_POSITIVE_ONLY = {"missing_header", "cookie_flag", "tls_version", "dns_record",
                  "cors_origin", "clickjacking", "certificate"}


class _Seq:
    def __init__(self) -> None:
        self._c = itertools.count(1)
        self._lock = threading.Lock()

    def next(self) -> int:
        with self._lock:
            return next(self._c)


_SEQ = _Seq()


@dataclass
class Finding:
    target: str
    category: str
    title: str
    severity: str
    description: str
    evidence: str = ""
    detection_method: str = ""
    confidence: str = NEEDS_MANUAL
    cwe: str | None = None
    cve: str | None = None
    remediation: str = ""
    url: str = ""
    parameter: str = ""
    module: str = ""
    finding_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    verification_status: str = "UNVERIFIED"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            self.severity = INFO
        if self.confidence not in _CONF_RANK:
            self.confidence = NEEDS_MANUAL
        if not self.finding_id:
            self.finding_id = f"TSMSS-{_SEQ.next():04d}"
        if not self.url:
            self.url = self.target
        if not self.verification_status or self.verification_status == "UNVERIFIED":
            self.verification_status = ("AUTO-VERIFIED" if self.confidence == CONFIRMED
                                        else "MANUAL-REVIEW-REQUIRED")

    def downgrade_if_heuristic(self, kind: str) -> "Finding":
        """Prevent CONFIRMED on classes that only support inference."""
        if kind not in _POSITIVE_ONLY and self.confidence == CONFIRMED:
            self.confidence = HIGH_CONF
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def weight(self) -> int:
        from config import SEVERITY_WEIGHTS
        return SEVERITY_WEIGHTS[self.severity]


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 99


# --- scoring: the single source of truth -------------------------------
# Saturating deduction. A cap per severity stops a noisy target from
# flooring the score at 0, while k controls how fast each class approaches
# its cap, so repeats always cost less than first occurrences.
_DEDUCTION_CAP = {"CRITICAL": 90.0, "HIGH": 25.0, "MEDIUM": 12.0, "LOW": 5.0, "INFO": 0.0}
_DEDUCTION_K = {"CRITICAL": 3.0, "HIGH": 5.0, "MEDIUM": 8.0, "LOW": 15.0, "INFO": 1.0}


def score_counts(counts: dict[str, int]) -> tuple[int, str]:
    """Score a severity histogram. Used by the engine and by every report."""
    deduction = sum(
        _DEDUCTION_CAP[sev] * n / (n + _DEDUCTION_K[sev])
        for sev, n in counts.items() if sev in _DEDUCTION_CAP and n
    )
    value = max(0, min(100, round(100 - deduction)))
    grade = ("A" if value >= 90 else "B" if value >= 80 else "C" if value >= 65
             else "D" if value >= 50 else "E" if value >= 30 else "F")
    return value, grade