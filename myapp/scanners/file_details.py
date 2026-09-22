"""Additional bounded static metadata. Samples are never extracted or executed."""

import ipaddress
import re
import struct
from .target import module_result
from .web_analysis import javascript


def details(data, name):
    text = data[: 2 * 1024 * 1024].decode("utf-8", errors="replace")
    strings = [
        x.decode("ascii")[:240]
        for x in re.findall(rb"[\x20-\x7e]{6,240}", data[: 2 * 1024 * 1024])[:200]
    ]
    ips = []
    for value in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)):
        try:
            ips.append(str(ipaddress.ip_address(value)))
        except ValueError:
            pass
    domains = sorted(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b", text)))[
        :200
    ]
    emails = sorted(set(re.findall(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", text)))[:100]
    hashes = sorted(
        set(
            re.findall(
                r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})\b",
                text,
            )
        )
    )[:100]
    # Raw strings can contain secrets; expose counts and non-secret IOC candidates only.
    rows = [
        module_result(
            "strings",
            name,
            "file",
            data={
                "printable_sample_count": len(strings),
                "redacted_sample": [
                    "[REDACTED]"
                    if re.search(
                        r"(?i)password|token|secret|api.?key|private key|bearer", x
                    )
                    else x
                    for x in strings[:50]
                ],
                "sample_bytes_inspected": min(len(data), 2 * 1024 * 1024),
                "state": "Observed",
                "privacy": "Common credential labels are redacted; evidence can still contain sensitive sample content.",
            },
        ),
        module_result(
            "iocs",
            name,
            "file",
            data={
                "ips": ips[:100],
                "domains": domains,
                "emails": emails,
                "hashes": hashes,
                "assessment": "Unvalidated static candidates; no malicious reputation inferred.",
            },
        ),
        module_result(
            "script",
            name,
            "file",
            data={
                "indicators": javascript(text),
                "assessment": "Potential indicators, not proof of execution.",
            },
        ),
    ]
    command = re.search(r"(?i)\bpowershell(?:\.exe)?\s+[^\r\n]{0,120}?-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{8,}", text)
    if command:
        rows.append(module_result("script_command", name, "file", findings=[{
            "title": "Potential encoded PowerShell command",
            "severity": "MEDIUM", "confidence": "medium",
            "description": "Static command syntax was observed; execution has not been observed.",
            "category": "Static command indicator", "evidence": {"command_prefix": command.group()[:180]},
            "source": "local static command rule", "mitre_technique": "T1059.001", "mitre_tactic": "Execution",
            "recommendation": "Review the command and file origin without running the sample."
        }]))
    if data.startswith(b"\x7fELF"):
        rows.append(
            module_result(
                "elf",
                name,
                "file",
                data={
                    "class": {1: "32-bit", 2: "64-bit"}.get(
                        data[4] if len(data) > 4 else 0, "Unknown"
                    ),
                    "endianness": {1: "little", 2: "big"}.get(
                        data[5] if len(data) > 5 else 0, "Unknown"
                    ),
                    "limitation": "Header identification only; no disassembly.",
                },
            )
        )
    if data.startswith(b"MZ"):
        pe = {
            "state": "Unverified DOS header",
            "limitation": "No execution, disassembly or signature trust assessment.",
        }
        if len(data) >= 64:
            offset = struct.unpack_from("<I", data, 60)[0]
            if offset + 24 <= len(data) and data[offset : offset + 4] == b"PE\0\0":
                machine, sections, timestamp = struct.unpack_from(
                    "<HHI", data, offset + 4
                )
                pe.update(
                    state="Observed PE header",
                    machine=hex(machine),
                    sections=sections,
                    coff_timestamp=timestamp,
                )
        rows.append(module_result("pe", name, "file", data=pe))
    from .optional_tools import analyze

    rows.extend(analyze(data, name))
    rows.append(
        module_result(
            "timestamps",
            name,
            "file",
            "unsupported",
            data={
                "detail": "Original filesystem paths and timestamps are not provided by browser uploads."
            },
        )
    )
    return rows
