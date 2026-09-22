"""Shared reviewed IOC matching.
Finding.ioc: status MATCHED/NOT_OBSERVED/UNAVAILABLE; checked [{ioc_type,value}],
matches [{ioc_type,value,source,threat_name,confidence,first_seen,last_seen}],
indicator_values [value], related_findings [id], note. A miss is never a safety verdict.
Local file entries are matched read-only; only explicit sync/import or qualified
existing provider results create durable indicators. Upserts never revive retired rows.
"""

import ipaddress
import json
import logging
import re
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit
from django.conf import settings
from django.db import transaction
from django.db.models import F
from django.utils import timezone


@lru_cache(maxsize=8)
def _load(path, mtime, size):
    try:
        with open(path, encoding="utf-8") as stream:
            data = json.load(stream)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        logging.getLogger(__name__).warning(
            "Reviewed local indicator file unavailable or invalid"
        )
        return {}


def load_local_iocs():
    path = settings.BASE_DIR / "data/local_iocs.json"
    try:
        stat = path.stat()
        return _load(str(path), stat.st_mtime_ns, stat.st_size)
    except OSError:
        logging.getLogger(__name__).warning("Reviewed local indicator file unavailable")
        return {}


def normalize_indicator(kind, value):
    from myapp.models import IndicatorOfCompromise

    if kind not in dict(IndicatorOfCompromise.IOC_TYPES):
        raise ValueError("Invalid IOC type")
    if not isinstance(value, str):
        raise ValueError("IOC value must be text")
    value = value.strip()
    if not value or len(value) > 1000:
        raise ValueError("Empty or oversized IOC")
    if kind == "HASH":
        if not re.fullmatch(
            r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})",
            value,
        ):
            raise ValueError("Invalid hash")
        value = value.lower()
    elif kind == "IP":
        value = str(ipaddress.ip_address(value))
    elif kind == "DOMAIN":
        value = value.lower().rstrip(".").encode("idna").decode("ascii")
        if not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value
        ):
            raise ValueError("Invalid domain")
    elif kind == "URL":
        p = urlsplit(value)
        if (
            p.scheme.lower() not in {"http", "https"}
            or not p.hostname
            or p.username
            or any(c.isspace() for c in value)
        ):
            raise ValueError("Invalid URL")
        value = urlunsplit(
            (p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, p.fragment)
        )
    elif kind == "EMAIL":
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Invalid email")
        value = value.lower()
    if kind == "REGISTRY":
        value=value.replace("/","\\").casefold()
        roots={"hklm":"hkey_local_machine","hkcu":"hkey_current_user","hkcr":"hkey_classes_root","hku":"hkey_users","hkcc":"hkey_current_config"}
        head,separator,tail=value.partition("\\")
        value=roots.get(head,head)+separator+tail
    elif kind == "FILENAME":
        value=value.replace("\\","/")
        if re.match(r"^[a-zA-Z]:",value):value=value.casefold()
    return {"ioc_type": kind, "value": value}


def local_entries():
    for key, kind in {"sha256": "HASH", "domains": "DOMAIN", "ips": "IP"}.items():
        for item in load_local_iocs().get(key, []):
            row = item if isinstance(item, dict) else {"value": item}
            try:
                indicator = normalize_indicator(kind, row.get("value"))
                confidence = row.get("confidence", 50)
                if type(confidence) != int or not 0 <= confidence <= 100:
                    continue
                yield dict(
                    indicator,
                    source="local_reviewed",
                    confidence=confidence,
                    threat_name=str(row.get("threat_name", "Reviewed local indicator"))[
                        :255
                    ],
                )
            except (ValueError, TypeError):
                continue


@transaction.atomic
def upsert_indicator(row, reactivate=False):
    from myapp.models import IndicatorOfCompromise

    normalized = normalize_indicator(row.get("ioc_type"), row.get("value"))
    source = str(row.get("source", "")).strip()
    confidence = row.get("confidence", 50)
    if not source or len(source) > 200:
        raise ValueError("A non-empty source is required (max 200 characters)")
    if type(confidence) != int or not 0 <= confidence <= 100:
        raise ValueError("Confidence must be an integer from 0 to 100")
    queryset = IndicatorOfCompromise.objects.select_for_update().filter(
        **normalized, source=source
    )
    obj = queryset.order_by("pk").first()
    values = {
        "confidence": confidence,
        "threat_name": str(row.get("threat_name", ""))[:255],
    }
    if obj:
        for key, value in values.items():
            setattr(obj, key, value)
        if reactivate:
            obj.is_active = True
        obj.save(update_fields=list(values) + (["is_active"] if reactivate else []))
        return obj, False
    return IndicatorOfCompromise.objects.create(
        **normalized, source=source, is_active=True, **values
    ), True


def clean_indicators(indicators):
    found = {}
    for row in indicators[:500]:
        try:
            item = normalize_indicator(row.get("ioc_type"), row.get("value"))
            found[(item["ioc_type"], item["value"])] = item
        except (ValueError, TypeError, AttributeError):
            continue
    return list(found.values())


def correlate_indicators(indicators):
    from myapp.models import IndicatorOfCompromise

    checked = clean_indicators(indicators)
    matches = []
    now = timezone.now()
    observed = set()
    for kind in sorted({x["ioc_type"] for x in checked}):
        values = [x["value"] for x in checked if x["ioc_type"] == kind]
        rows = list(
            IndicatorOfCompromise.objects.filter(ioc_type=kind, value__in=values)
        )
        # Retired local rows override the same still-present file entry.
        retired = {
            x.value for x in rows if x.source == "local_reviewed" and not x.is_active
        }
        for obj in rows:
            if not obj.is_active:
                continue
            matches.append(
                dict(
                    ioc_type=kind,
                    value=obj.value,
                    source=obj.source,
                    threat_name=obj.threat_name,
                    confidence=obj.confidence,
                    first_seen=obj.discovered_at.isoformat(),
                    last_seen=now.isoformat(),
                )
            )
            observed.add((kind, obj.value, obj.source))
        ids = [x.pk for x in rows if x.is_active]
        if ids:
            IndicatorOfCompromise.objects.filter(pk__in=ids).update(
                matches_found=F("matches_found") + 1, last_seen=now
            )
        for row in local_entries():
            key = (kind, row["value"], row["source"])
            if (
                row["ioc_type"] == kind
                and row["value"] in values
                and row["value"] not in retired
                and key not in observed
            ):
                matches.append(dict(row, first_seen=None, last_seen=now.isoformat()))
                observed.add(key)
    return matches


def extract_indicators(raw):
    result = []
    types = {
        "sha256": "HASH",
        "sha1": "HASH",
        "md5": "HASH",
        "hashes": "HASH",
        "hash": "HASH",
        "ip": "IP",
        "ips": "IP",
        "ip_address": "IP",
        "gateway": "IP",
        "dns_servers": "IP",
        "domain": "DOMAIN",
        "domains": "DOMAIN",
        "hostname": "DOMAIN",
        "url": "URL",
        "urls": "URL",
        "email": "EMAIL",
        "emails": "EMAIL",
    }

    def walk(value, depth=0):
        if depth > 6 or len(result) >= 500:
            return
        if isinstance(value, dict):
            if "ioc_type" in value and "value" in value:
                result.append(value)
            for key, item in value.items():
                if key.lower() in types:
                    for entry in item if isinstance(item, list) else [item]:
                        if isinstance(entry, str):
                            result.append(
                                {"ioc_type": types[key.lower()], "value": entry}
                            )
                if key == "records" and isinstance(item, list):
                    for entry in item:
                        try:
                            result.append(normalize_indicator("IP", entry))
                        except (ValueError, TypeError):
                            pass
                walk(item, depth + 1)
        elif isinstance(value, list):
            for item in value[:500]:
                walk(item, depth + 1)

    walk(raw)
    return clean_indicators(result)


def correlation_payload(raw, user=None, exclude_id=None):
    checked = extract_indicators(raw)
    payload = dict(
        status="NOT_OBSERVED",
        checked=checked,
        matches=[],
        indicator_values=[x["value"] for x in checked],
        related_findings=[],
        note="Not Observed in local indicator set",
    )
    try:
        with transaction.atomic():
            payload["matches"] = correlate_indicators(checked)
        if payload["matches"]:
            payload["status"] = "MATCHED"
            payload["note"] = "Matched reviewed indicator; validate source and context."
            if user:
                from myapp.models import Finding

                candidates = (
                    Finding.objects.filter(job__requested_by=user)
                    .exclude(pk=exclude_id)
                    .order_by("-timestamp")[:500]
                )
                values = {x["value"] for x in payload["matches"]}
                for finding in candidates:
                    if isinstance(finding.ioc, dict) and values.intersection(
                        finding.ioc.get("indicator_values", [])
                    ):
                        payload["related_findings"].append(finding.pk)
                        if len(payload["related_findings"]) >= 20:
                            break
    except Exception:
        payload.update(
            status="UNAVAILABLE",
            note="IOC check unavailable",
            matches=[],
            related_findings=[],
        )
    return payload


def persist_provider_results(results, target, target_type):
    # Only already-performed lookups are consumed. Breach-account results are never IOCs.
    kind = {"ip": "IP", "domain": "DOMAIN", "url": "URL", "hash": "HASH"}.get(
        target_type
    )
    if not kind:
        return
    try:
        normalized = normalize_indicator(kind, target)
        if kind == "IP" and not ipaddress.ip_address(normalized["value"]).is_global:
            return
    except (ValueError, TypeError):
        return
    for row in results:
        if not isinstance(row, dict) or row.get("status") != "success":
            continue
        provider = str(row.get("provider", ""))
        data = row.get("data", {})
        if any(x in provider.lower() for x in ("hibp", "pwned")):
            continue
        if not isinstance(data, dict):
            continue
        detections = data.get("detections", {})
        malicious = (
            detections.get("malicious", 0) if isinstance(detections, dict) else 0
        )
        report = data.get("report", {})
        abuse = report.get("abuseConfidenceScore", 0) if isinstance(report, dict) else 0
        confidence = None
        if isinstance(abuse, (int, float)) and abuse >= settings.IOC_MIN_ABUSE_SCORE:
            confidence = min(100, int(abuse))
        elif isinstance(malicious, int) and malicious >= settings.IOC_MIN_DETECTIONS:
            total = sum(x for x in detections.values() if isinstance(x, int) and x >= 0)
            confidence = round(100 * malicious / max(1, total))
        threat_name = "Reported reputation indicator"
        pulses = data.get("pulse_count")
        if (
            confidence is None
            and isinstance(pulses, int)
            and pulses >= getattr(settings, "IOC_MIN_OTX_PULSES", 3)
        ):
            # OTX reports pulse membership, not calibrated confidence. Zero means not supplied.
            confidence = 0
            names = [
                str(x.get("name", ""))
                for x in data.get("pulses", [])
                if isinstance(x, dict) and x.get("name")
            ]
            threat_name = (
                "OTX pulse membership (confidence not supplied): " + "; ".join(names)
            )
        if confidence is None:
            continue
        try:
            upsert_indicator(
                dict(
                    normalized,
                    source=provider,
                    confidence=confidence,
                    threat_name=threat_name,
                )
            )
        except Exception:
            logging.getLogger(__name__).warning("Indicator persistence unavailable")


# Stable public names used by scanner and command integrations.
correlation_block = correlation_payload
reviewed_entries = local_entries
