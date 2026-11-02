"""Phase 4: Proof Artifact Store & proof.md Generation.

Each confirmed finding produces:
1. request dump (curl -v style)
2. response slice (1KB window around the oracle)
3. sha256 of full response
4. ISO timestamp
5. tool name + version
6. For XSS: screenshot / WebM artifact paths
7. Stored under: $TMPDIR/art/<scanid>/<findingid>/
8. Writes proof.md linking every artifact.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from paths import resolve_temp_dir

logger = logging.getLogger("tsmss.verification.artifacts")


@dataclass
class ProofArtifact:
    finding_id: str
    scan_id: str
    tool_version: str
    timestamp: str
    request_dump: str
    response_slice: str
    response_sha256: str
    oracle_name: str
    target_url: str
    finding_title: str
    severity: str
    confidence: str
    media_paths: list[str] = field(default_factory=list)
    artifact_dir: Path | None = None


class ArtifactStore:
    """Manages storing proof artifacts under $TMPDIR/art/<scanid>/<findingid>/."""

    def __init__(self, scan_id: str, base_temp_dir: Path | None = None):
        self.scan_id = scan_id
        temp_base = base_temp_dir or resolve_temp_dir(abort_on_failure=True)
        self.art_root = temp_base / "art" / scan_id
        self.art_root.mkdir(parents=True, exist_ok=True)
        self.artifacts: list[ProofArtifact] = []

    def store_finding_artifact(
        self,
        finding_id: str,
        target_url: str,
        finding_title: str,
        severity: str,
        confidence: str,
        request_dump: str,
        response_body: str,
        oracle_name: str,
        response_slice: str = "",
        tool_version: str = "tsmss-2.0-verify",
        media_files: list[Path | str] | None = None,
    ) -> ProofArtifact:
        """Store request dump, 1KB response window, sha256, and metadata for a finding."""
        finding_dir = self.art_root / finding_id
        finding_dir.mkdir(parents=True, exist_ok=True)

        iso_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        body_bytes = response_body.encode("utf-8", "ignore") if isinstance(response_body, str) else bytes(response_body)
        resp_hash = hashlib.sha256(body_bytes).hexdigest()

        # Compute 1KB slice around oracle if slice not already computed
        if not response_slice and response_body:
            response_slice = response_body[:1024]
        elif len(response_slice) > 1024:
            response_slice = response_slice[:1024]

        # 1. request.txt
        req_file = finding_dir / "request.txt"
        req_file.write_text(request_dump or f"> GET {target_url} HTTP/1.1\n> Host: {target_url}\n", encoding="utf-8")

        # 2. response_slice.txt (1KB window around oracle)
        slice_file = finding_dir / "response_slice.txt"
        slice_file.write_text(response_slice, encoding="utf-8")

        # 3. meta.json
        meta_data = {
            "finding_id": finding_id,
            "scan_id": self.scan_id,
            "target_url": target_url,
            "title": finding_title,
            "severity": severity,
            "confidence": confidence,
            "oracle": oracle_name,
            "sha256": resp_hash,
            "timestamp": iso_ts,
            "tool_version": tool_version,
            "request_file": "request.txt",
            "response_slice_file": "response_slice.txt",
        }
        meta_file = finding_dir / "meta.json"
        meta_file.write_text(json.dumps(meta_data, indent=2), encoding="utf-8")

        # Copy any media files (screenshots, recordings) into finding_dir
        saved_media: list[str] = []
        for mf in (media_files or []):
            src = Path(mf)
            if src.exists():
                dst = finding_dir / src.name
                if src != dst:
                    dst.write_bytes(src.read_bytes())
                saved_media.append(str(dst))

        artifact = ProofArtifact(
            finding_id=finding_id,
            scan_id=self.scan_id,
            tool_version=tool_version,
            timestamp=iso_ts,
            request_dump=request_dump,
            response_slice=response_slice,
            response_sha256=resp_hash,
            oracle_name=oracle_name,
            target_url=target_url,
            finding_title=finding_title,
            severity=severity,
            confidence=confidence,
            media_paths=saved_media,
            artifact_dir=finding_dir,
        )
        self.artifacts.append(artifact)
        return artifact

    def write_proof_md(self, destination: Path | None = None) -> Path:
        """Write proof.md linking every artifact, its hash, timestamp, and oracle."""
        dest = destination or (self.art_root / "proof.md")
        lines = [
            f"# TSMSS Verification Proof Manifest",
            f"**Scan ID:** `{self.scan_id}`  ",
            f"**Generated:** `{datetime.datetime.now(datetime.timezone.utc).isoformat()}`  ",
            f"**Total Confirmed Artifacts:** {len(self.artifacts)}\n",
            "| Finding ID | Severity | Confidence | Title | Oracle | SHA-256 | Artifacts |",
            "|---|---|---|---|---|---|---|",
        ]

        for art in self.artifacts:
            art_dir_str = str(art.artifact_dir) if art.artifact_dir else ""
            req_link = f"[`request.txt`](file:///{art_dir_str.replace('\\', '/')}/request.txt)"
            slice_link = f"[`response_slice.txt`](file:///{art_dir_str.replace('\\', '/')}/response_slice.txt)"
            media_links = " ".join([f"[`{Path(p).name}`](file:///{p.replace('\\', '/')})" for p in art.media_paths])
            all_links = f"{req_link} {slice_link} {media_links}".strip()

            short_hash = art.response_sha256[:12] + "..." if art.response_sha256 else "N/A"
            lines.append(
                f"| `{art.finding_id}` | **{art.severity}** | `{art.confidence}` | {art.finding_title} | {art.oracle_name} | `{short_hash}` | {all_links} |"
            )

        lines.append("\n## Detailed Proof Artifacts\n")
        for art in self.artifacts:
            lines.append(f"### Finding `{art.finding_id}`: {art.finding_title}")
            lines.append(f"- **Target:** `{art.target_url}`")
            lines.append(f"- **Severity:** `{art.severity}` | **Confidence:** `{art.confidence}`")
            lines.append(f"- **Verification Oracle:** {art.oracle_name}")
            lines.append(f"- **Timestamp:** `{art.timestamp}` | **Tool Version:** `{art.tool_version}`")
            lines.append(f"- **Response Full SHA-256:** `{art.response_sha256}`")
            lines.append(f"\n**Request Dump:**\n```http\n{art.request_dump}\n```\n")
            lines.append(f"**Response Slice (1KB Oracle Window):**\n```html\n{art.response_slice}\n```\n")
            if art.media_paths:
                lines.append("**Attached Evidence Media:**")
                for mp in art.media_paths:
                    lines.append(f"- `file:///{mp.replace('\\', '/')}`")
            lines.append("\n---\n")

        content = "\n".join(lines) + "\n"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        return dest
