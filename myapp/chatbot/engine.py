from __future__ import annotations
import re
from django.urls import reverse

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet: unencrypted remote access",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB: restrict file sharing",
    993: "IMAPS",
    995: "POP3S",
    1433: "SQL Server",
    3306: "MySQL",
    3389: "RDP: restrict remote access",
    5432: "PostgreSQL",
    5900: "VNC: restrict desktop access",
    6379: "Redis: never expose unauthenticated",
    8080: "HTTP-alt",
    27017: "MongoDB: restrict database access",
}
from .intents import ALIASES, CONCEPTS


def _normalize(text):
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]", " ", (text or "").lower())).strip()


def _find(text):
    best, points = None, 0
    for intent, aliases in ALIASES.items():
        score = max(
            (
                len(alias.split())
                for alias in aliases
                if re.search(r"\b" + re.escape(alias) + r"\b", text)
            ),
            default=0,
        )
        if score > points:
            best, points = intent, score
    return best


def _record_answer(message, user):
    from myapp.models import Finding, ScanJob, ScanResult, WiFiAudit

    text, intent = _normalize(message), _find(_normalize(message))
    if re.search(r"t\d{4}", text):
        from myapp.mitre_data import dataset

        match = re.search(r"t\d{4}(?:\s+\d{3})?", text)
        if match:
            technique_id = match.group().upper().replace(" ", ".")
            row = next(
                (r for r in dataset()["techniques"] if r["id"] == technique_id), None
            )
            if row:
                return {
                    "intent": "mitre_lookup",
                    "source": "local_knowledge",
                    "live_data": False,
                    "response": row["id"]
                    + " "
                    + row["name"]
                    + "\n"
                    + row["description"]
                    + "\nTactics: "
                    + ", ".join(row.get("tactics", []))
                    + "\nPlatforms: "
                    + ", ".join(row.get("platforms", []))
                    + "\nDetection: "
                    + str(row.get("detection", "Not supplied"))
                    + "\n"
                    + "\n".join(row.get("detection_guidance", []))
                    + "\nMitigations: "
                    + "\n".join(
                        x["name"] + ": " + x["description"]
                        for x in row.get("mitigations", [])
                    )
                    + "\nReference: "
                    + row["reference"],
                }
    if not intent:
        return {
            "intent": "unknown",
            "source": "unknown",
            "live_data": False,
            "response": "I can answer cybersecurity concepts plus questions about your latest scan, findings, risk, open ports, and Wi-Fi audit. Try: What did my last scan find? What ports are open? What is WPA3?",
        }
    if intent == "threat_finding":
        latest = (
            ScanJob.objects.filter(
                requested_by=user, status__in=["COMPLETED", "PARTIAL"]
            )
            .order_by("-completed_at")
            .first()
        )
        if not latest:
            return {
                "intent": intent,
                "source": "live_scan",
                "live_data": True,
                "response": "NO DATA: no completed local scan job is available for your account.",
            }
        rows = latest.findings.order_by("-risk_score")[:5]
        summary = (
            "; ".join(
                f"{x.severity}: {x.title}\nConfidence: {x.confidence}; status: {x.status}\nEvidence: {str(x.evidence)[:1200]}\nRemediation: {x.recommendation}\nType: {x.finding_type}; MITRE: {x.mitre_technique or 'No Evidence'} {x.mitre_tactic}\nFinding: {reverse('finding_detail', args=[x.pk])}"
                for x in rows
            )
            or "no normalized findings"
        )
        return {
            "intent": intent,
            "source": "live_scan",
            "live_data": True,
            "response": f"Latest scan {latest.scan_id[:8]} is {latest.status} with risk {latest.risk_score}/100. Findings: {summary}.",
        }
    if intent in {
        "critical_severity",
        "high_severity",
        "medium_severity",
        "low_severity",
    }:
        severity = intent.split("_")[0].upper()
        count = Finding.objects.filter(
            job__requested_by=user, severity=severity
        ).count()
        return {
            "intent": intent,
            "source": "live_scan",
            "live_data": True,
            "response": (
                f"Your stored scan findings include {count} {severity} finding(s).\n"
                + "\n".join(
                    f"- {f.title}: {f.recommendation[:350]}\n{reverse('finding_detail', args=[f.pk])}"
                    for f in Finding.objects.filter(
                        job__requested_by=user, severity=severity
                    ).order_by("-timestamp")[:10]
                )
                if Finding.objects.filter(job__requested_by=user).exists()
                else "NO DATA: no findings stored for your account."
            ),
        }
    if intent == "open_port":
        latest = ScanResult.objects.filter(user=user).order_by("-created_at").first()
        ports = latest.open_ports if latest else []
        return {
            "intent": intent,
            "source": "live_scan",
            "live_data": True,
            "response": (
                "NO DATA: no saved scan result contains port data."
                if not ports
                else "Recorded ports: "
                + ", ".join(
                    str(x.get("port", "unknown"))
                    + " ("
                    + PORT_SERVICES.get(x.get("port"), "No local service mapping")
                    + ")"
                    for x in ports[:30]
                )
                + "."
            ),
        }
    if intent == "risk_score":
        latest = (
            ScanJob.objects.filter(
                requested_by=user, status__in=["COMPLETED", "PARTIAL"]
            )
            .order_by("-completed_at")
            .first()
        )
        return {
            "intent": intent,
            "source": "live_scan",
            "live_data": True,
            "response": f"Current completed local-job risk is {latest.risk_score}/100.\nRecorded contributors:\n"
            + "\n".join(
                f"- {f.title}: {f.risk_score} points; {f.severity}"
                for f in latest.findings.order_by("-risk_score")[:10]
            )
            if latest
            else "NO DATA: no completed scan job is available.",
        }
    if intent == "wifi_audit":
        rows = WiFiAudit.objects.filter(user=user).order_by("-created_at")
        if not rows.exists():
            return {
                "intent": intent,
                "source": "wifi_audit",
                "live_data": True,
                "response": "NO DATA: no Wi-Fi audit is stored for your account.",
            }
        latest_time = rows.first().created_at
        latest = rows.filter(created_at__gte=latest_time.replace(microsecond=0))[:50]
        return {
            "intent": intent,
            "source": "wifi_audit",
            "live_data": True,
            "response": "Latest Wi-Fi audit profiles: "
            + "; ".join(
                f"{x.profile_name} ({x.security_level}, {x.risk_level}): {x.risk_reason}\n{x.recommendation}"
                for x in latest
            )
            + ".",
        }
    return {
        "intent": intent,
        "source": "local_knowledge",
        "live_data": False,
        "response": CONCEPTS[intent],
    }


LIVE_INTENTS = {
    "threat_finding",
    "critical_severity",
    "high_severity",
    "medium_severity",
    "low_severity",
    "open_port",
    "risk_score",
    "wifi_audit",
}


def answer(message, user, history=None):
    """Retrieve local guidance or user-owned records without claiming LLM generation."""
    from .knowledge import ARTICLES
    from myapp.presentation import display

    text = _normalize(message)
    intent = _find(text)
    if intent in LIVE_INTENTS or re.search(r"t\d{4}", text):
        result = _record_answer(message, user)
        if result["live_data"]:
            result["response"] += (
                "\n\n## Interpretation\nThese are stored observations for your account, not a current continuous monitoring feed. A missing finding or zero score does not establish safety.\n\n## Next steps\nOpen the related scan job, inspect evidence and collection errors, and validate the affected target before changing finding status or escalating an incident."
            )
        return display(result)
    query = set(text.split())
    ranked = sorted(
        (
            (len(query & set(article["terms"].split())), key, article)
            for key, article in ARTICLES.items()
        ),
        reverse=True,
    )
    # Short follow-up questions may reuse recent topic context, never asserted evidence.
    if (
        ranked[0][0] == 0
        and history
        and any(x in query for x in {"it", "that", "more", "example", "explain", "why"})
    ):
        prior = " ".join(
            str(x.get("text", ""))[:1000] for x in history[-4:] if isinstance(x, dict)
        )
        query |= set(_normalize(prior).split())
        ranked = sorted(
            (
                (len(query & set(article["terms"].split())), key, article)
                for key, article in ARTICLES.items()
            ),
            reverse=True,
        )
    selected = [row for row in ranked if row[0] > 0][:2]
    if selected:
        parts = []
        for _, key, article in selected:
            parts.append(
                "## "
                + article["title"]
                + "\n"
                + article["explanation"]
                + "\n\n### Practical approach\n"
                + article["steps"]
                + "\n\n### Example\n"
                + article["example"]
                + "\n\n### In Vigilant Sphere\n"
                + article["application"]
            )
        response = "\n\n".join(parts)
        response += "\n\nSource: local security guidance. This answer does not assert that your device or target has been compromised. Tell me which observation you want to investigate, or ask about your latest scan for account-specific records."
        return display(
            {
                "intent": "local_retrieval",
                "source": "local_knowledge",
                "live_data": False,
                "response": response,
            }
        )
    result = _record_answer(message, user)
    if result["intent"] == "unknown":
        result["response"] = (
            "I do not have enough relevant local material to answer that reliably. I am a local knowledge assistant, not a connected language model.\n\nDescribe the security question using the affected asset, the observed behavior, and what you want to decide. Do not include passwords or tokens. I can help interpret file indicators, suspicious links, network observations, wireless settings, incident workflows, application security, and ATT&CK techniques.\n\nFor your own evidence, ask about your latest scan, findings, risk score, open ports, or saved Wi-Fi audit. I will distinguish stored observations from missing data."
        )
    else:
        result["response"] += (
            "\n\n### How to use this explanation\nSeparate a general security concept from evidence about a specific system. Record what was actually observed, when it was collected, and any collection limitations. Explain the target and the decision you need to make for a more focused answer.\n\n### Evidence in this application\nUse saved scan jobs and linked findings for investigation. A capability marked unavailable has not produced a negative result. Technique mappings describe an evidence relationship and do not establish an attack by themselves."
        )
    return display(result)
