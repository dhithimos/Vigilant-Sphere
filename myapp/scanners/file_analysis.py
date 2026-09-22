"""Static in-memory file analysis; uploaded bytes are never executed or persisted."""

from __future__ import annotations

import hashlib
import math
import mimetypes
import os
import re
import zipfile
from collections import Counter
from io import BytesIO

from .target import module_result

MAGIC = [
    (b"MZ", "PE executable"),
    (b"%PDF-", "PDF"),
    (b"PK\x03\x04", "ZIP container"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
]
URL_RE = re.compile(rb"https?://[^\s\"'<>]{3,2048}", re.I)


def _entropy(data):
    if not data:
        return 0.0
    total = len(data)
    return round(
        -sum((n / total) * math.log2(n / total) for n in Counter(data).values()), 3
    )


def analyze_uploaded(uploaded):
    name = os.path.basename(uploaded.name).replace("\x00", "")[:255]
    from django.conf import settings

    data = uploaded.read(settings.MAX_UPLOAD_SIZE + 1)
    if len(data) > settings.MAX_UPLOAD_SIZE:
        raise ValueError("Upload exceeds size limit.")
    uploaded.seek(0)
    hashes = {
        x: getattr(hashlib, x)(data).hexdigest()
        for x in ("md5", "sha1", "sha256", "sha512")
    }
    mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
    detected = next(
        (label for sig, label in MAGIC if data.startswith(sig)),
        "Unknown / generic data",
    )
    findings, metadata = (
        [],
        {
            "filename": name,
            "extension": os.path.splitext(name)[1].lower(),
            "size": len(data),
            "mime_type": mime,
            "mime_note": "Extension-derived hint; not trusted for execution or safety",
            "detected_type": detected,
            "magic_bytes": data[:16].hex(),
            "entropy": _entropy(data),
        },
    )
    if metadata["entropy"] >= 7.5:
        findings.append(
            {
                "title": "High-entropy content",
                "severity": "MEDIUM",
                "confidence": "medium",
                "category": "File analysis",
                "description": "High entropy can occur in compressed or encrypted content and requires context.",
                "evidence": f"Entropy: {metadata['entropy']} bits per byte",
                "source": "local static analysis",
                "recommendation": "Review file origin and container type before opening.",
            }
        )
    extracted_urls = sorted(
        {u.decode("utf-8", errors="replace") for u in URL_RE.findall(data)}
    )[:200]
    results = [
        module_result("file_metadata", name, "file", data=metadata),
        module_result("hashes", name, "file", data=hashes),
        module_result(
            "file_indicators",
            name,
            "file",
            data={"urls": extracted_urls},
            findings=findings,
        ),
    ]
    if zipfile.is_zipfile(BytesIO(data)):
        try:
            with zipfile.ZipFile(BytesIO(data)) as archive:
                members = archive.infolist()[:1000]
                uncompressed = sum(x.file_size for x in archive.infolist())
                compressed = sum(x.compress_size for x in archive.infolist())
                suspicious = [
                    x.filename
                    for x in members
                    if ".." in x.filename.replace("\\", "/").split("/")
                    or os.path.splitext(x.filename)[1].lower()
                    in {".exe", ".dll", ".js", ".vbs", ".ps1", ".docm", ".xlsm"}
                ]
                if any(
                    x.filename.startswith(("word/", "xl/", "ppt/")) for x in members
                ):
                    results.append(
                        module_result(
                            "office",
                            name,
                            "file",
                            data={
                                "state": "Observed OOXML container",
                                "macro_members": [
                                    x.filename
                                    for x in members
                                    if "vbaproject" in x.filename.lower()
                                ],
                                "embedded_members": [
                                    x.filename
                                    for x in members
                                    if "/embeddings/" in x.filename
                                ],
                                "limitation": "Container metadata only; embedded objects not extracted.",
                            },
                        )
                    )
                ratio = round(uncompressed / max(compressed, 1), 2)
                archive_findings = []
                if ratio > 100 or uncompressed > 250 * 1024 * 1024:
                    archive_findings.append(
                        {
                            "title": "Potential archive expansion risk",
                            "severity": "HIGH",
                            "confidence": "high",
                            "category": "Archive safety",
                            "description": "Archive metadata indicates an unusually large expansion ratio or size.",
                            "evidence": {
                                "compression_ratio": ratio,
                                "uncompressed_bytes": uncompressed,
                            },
                            "source": "local static analysis",
                            "recommendation": "Do not extract without resource limits.",
                        }
                    )
                results.append(
                    module_result(
                        "archive",
                        name,
                        "file",
                        data={
                            "member_count": len(archive.infolist()),
                            "members": [
                                {
                                    "name": x.filename,
                                    "size": x.file_size,
                                    "compressed_size": x.compress_size,
                                    "encrypted": bool(x.flag_bits & 1),
                                }
                                for x in members
                            ],
                            "compression_ratio": ratio,
                            "suspicious_members": suspicious[:100],
                            "truncated": len(archive.infolist()) > len(members),
                        },
                        findings=archive_findings,
                    )
                )
        except (zipfile.BadZipFile, OSError) as exc:
            results.append(
                module_result(
                    "archive",
                    name,
                    "file",
                    "error",
                    errors=[f"Archive metadata unavailable: {exc.__class__.__name__}"],
                )
            )
    if data.startswith(b"%PDF-"):
        results.append(
            module_result(
                "pdf",
                name,
                "file",
                data={
                    "javascript_markers": data.count(b"/JavaScript")
                    + data.count(b"/JS"),
                    "embedded_file_markers": data.count(b"/EmbeddedFile"),
                    "url_count": len(extracted_urls),
                },
            )
        )
    from myapp.analysis.ioc_correlation import correlation_block, load_local_iocs
    block=correlation_block({"sha256":hashes["sha256"]})
    match=any(x["source"]=="local_reviewed" for x in block["matches"])
    results.append(module_result("local_ioc",name,"file","unavailable" if block["status"]=="UNAVAILABLE" else "success",data={"status":"Observed" if match else "Not Observed", "dataset_entries":len(load_local_iocs().get("sha256",[])),"exact_sha256_match":match,"note":"Operator-maintained indicators; no malware verdict inferred from absence.","ioc":block}))
    from .file_details import details

    results.extend(details(data, name))
    return results
