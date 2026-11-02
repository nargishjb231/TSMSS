"""Finding model with mandatory evidence, 4-tier verification, OWASP mapping, and baseline fingerprinting."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import itertools
import threading
from typing import Any

from config import SEVERITY_ORDER

CRITICAL, HIGH, MEDIUM, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
CONFIRMED = "CONFIRMED"
STRONG_EVIDENCE = "STRONG EVIDENCE"
POTENTIAL = "POTENTIAL"
HIGH_CONF = "HIGH CONFIDENCE"
MED_CONF = "MEDIUM CONFIDENCE"
LOW_CONF = "LOW CONFIDENCE"
NEEDS_MANUAL = "NEEDS MANUAL VERIFICATION"
HEURISTIC = "HEURISTIC"
MANUAL = "MANUAL REVIEW"

_CONF_RANK = {
    CONFIRMED: 5,
    STRONG_EVIDENCE: 4,
    HIGH_CONF: 4,
    POTENTIAL: 3,
    MED_CONF: 3,
    LOW_CONF: 2,
    NEEDS_MANUAL: 1,
    HEURISTIC: 1,
    MANUAL: 1,
}

# Checks that may only ever be CONFIRMED because they assert a positive fact.
_POSITIVE_ONLY = {
    "missing_header", "cookie_flag", "tls_version", "dns_record",
    "cors_origin", "clickjacking", "certificate",
}


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
    endpoint: str = ""
    owasp_reference: str = ""
    wstg_reference: str = ""
    impact: str = ""
    false_positive_notes: str = ""
    test_id: str = ""
    edge: bool = False
    csp_source: str = ""
    check_outcome: str = "ran"

    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = f"TSMSS-{_SEQ.next():05d}"
        self.severity = self.severity.upper()
        if self.severity not in SEVERITY_ORDER:
            self.severity = INFO
        if self.confidence not in _CONF_RANK:
            self.confidence = NEEDS_MANUAL
        if not self.evidence:
            self.evidence = "(no raw snippet captured)"
        if not self.url:
            self.url = self.target
        from core.verification import enrich_finding
        enrich_finding(self)

    def downgrade_if_heuristic(self, kind: str) -> "Finding":
        """Prevent CONFIRMED on classes that only support inference."""
        if kind not in _POSITIVE_ONLY and self.confidence == CONFIRMED:
            self.confidence = HIGH_CONF
            if self.verification_status == CONFIRMED:
                self.verification_status = STRONG_EVIDENCE
        return self

    def evidence_digest(self) -> str:
        raw = (self.evidence or "").encode("utf-8", "replace")
        return hashlib.sha256(raw).hexdigest()[:16]

    def check_key(self) -> str:
        return f"{self.title}|{self.parameter}" if self.parameter else self.title

    def fingerprint(self) -> tuple[str, str, str, str]:
        """Exact 4-tuple fingerprint: (module, target, check, evidence_digest)."""
        return (
            self.module or self.category,
            self.target,
            self.check_key(),
            self.evidence_digest(),
        )

    def fingerprint_dict(self) -> dict[str, str]:
        mod, tgt, chk, dig = self.fingerprint()
        return {
            "module": mod,
            "target": tgt,
            "check": chk,
            "evidence_digest": dig,
        }

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Include uppercase aliases required by Section 15 AI-Readable Report schema
        d["OWASP_reference"] = self.owasp_reference
        d["WSTG_reference"] = self.wstg_reference
        d["CWE"] = self.cwe
        d["CVE"] = self.cve
        return d

    def to_ai_dict(self) -> dict[str, Any]:
        """Return exact Section 15 AI-readable finding structure."""
        return {
            "finding_id": self.finding_id,
            "target": self.target,
            "endpoint": self.endpoint or self.url or self.target,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "verification_status": self.verification_status,
            "evidence": self.evidence,
            "detection_method": self.detection_method,
            "OWASP_reference": self.owasp_reference,
            "WSTG_reference": self.wstg_reference,
            "CWE": self.cwe,
            "CVE": self.cve,
            "impact": self.impact,
            "remediation": self.remediation,
            "false_positive_notes": self.false_positive_notes,
            "timestamp": self.timestamp,
            "module": self.module,
            "parameter": self.parameter,
            "test_id": self.test_id,
            "tags": list(self.tags),
        }

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
    """Score a severity histogram with J1 grade caps (any CRITICAL -> max B; any HIGH -> max A-)."""
    deduction = sum(
        _DEDUCTION_CAP[sev] * n / (n + _DEDUCTION_K[sev])
        for sev, n in counts.items() if sev in _DEDUCTION_CAP and n
    )
    value = max(0, min(100, round(100 - deduction)))
    grade = (
        "A" if value >= 90 else "B" if value >= 80 else "C" if value >= 65
        else "D" if value >= 50 else "E" if value >= 30 else "F"
    )
    # J1: Grade cap: any CRITICAL -> max grade B; any HIGH -> max grade A-
    if counts.get("CRITICAL", 0) > 0:
        if grade in ("A", "A-"):
            grade = "B"
    elif counts.get("HIGH", 0) > 0:
        if grade == "A":
            grade = "A-"
    return value, grade


def score_breakdown(counts: dict[str, int]) -> list[dict[str, Any]]:
    """Return the J3 weight/deduction table rows for a severity count map."""
    rows: list[dict[str, Any]] = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = int(counts.get(sev, 0) or 0)
        cap = _DEDUCTION_CAP[sev]
        k = _DEDUCTION_K[sev]
        ded = round(cap * n / (n + k), 2) if n else 0.0
        rows.append({"severity": sev, "count": n, "cap": cap, "k": k, "deduction": ded})
    return rows


def compute_global_score(
    target_scores: list[int],
    has_critical: bool = False,
    total_counts: dict[str, int] | None = None,
) -> tuple[int, str]:
    """J2: Global score = min(per_target_scores) when any CRITICAL exists, else mean(per_target_scores)."""
    counts = total_counts or {}
    if has_critical or counts.get("CRITICAL", 0) > 0:
        has_critical = True
    if not target_scores:
        return score_counts(counts)
    if has_critical:
        val = int(min(target_scores))
    else:
        val = int(round(sum(target_scores) / len(target_scores)))
    grade = (
        "A" if val >= 90 else "B" if val >= 80 else "C" if val >= 65
        else "D" if val >= 50 else "E" if val >= 30 else "F"
    )
    if has_critical and grade in ("A", "A-"):
        grade = "B"
    elif counts.get("HIGH", 0) > 0 and grade == "A":
        grade = "A-"
    return val, grade
