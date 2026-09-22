"""Small, isolated adapters. Provider failures are normalized, never treated as clean."""

from __future__ import annotations

import datetime as dt
import json
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


urlopen = build_opener(ProxyHandler({}), NoRedirect()).open

from django.conf import settings


def _result(provider, indicator, indicator_type, status, data=None, errors=None):
    return {
        "provider": provider,
        "indicator": indicator,
        "indicator_type": indicator_type,
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": status,
        "data": data or {},
        "errors": errors or [],
        "raw_available": False,
    }


def _request(url, headers, timeout=10):
    request = Request(url, headers=headers)
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read(1024 * 1024).decode("utf-8", errors="replace"))


def provider_status():
    return {
        "VirusTotal": "Configured" if settings.VT_API_KEY else "Not Configured",
        "AbuseIPDB": "Configured" if settings.ABUSEIPDB_API_KEY else "Not Configured",
        "AlienVault OTX": "Configured" if settings.OTX_API_KEY else "Not Configured",
        "HIBP email": "Configured"
        if settings.HIBP_API_KEY and settings.HIBP_EMAIL_CHECK_ENABLED
        else "Not Configured",
        "HIBP passwords": "Available"
        if settings.HIBP_PASSWORDS_ENABLED
        else "Disabled",
    }


def _error(provider, indicator, kind, exc):
    if isinstance(exc, HTTPError):
        status = (
            "rate_limited"
            if exc.code == 429
            else "authentication_error"
            if exc.code in {401, 403}
            else "provider_error"
        )
    elif isinstance(exc, (URLError, TimeoutError)):
        status = "unavailable"
    else:
        status = "malformed_response"
    return _result(
        provider,
        indicator,
        kind,
        status,
        errors=[f"{exc.__class__.__name__}; no provider result was obtained."],
    )


def virustotal(indicator, kind):
    if not settings.VT_API_KEY:
        return _result("VirusTotal", indicator, kind, "not_configured")
    endpoint_type = {
        "hash": "files",
        "url": "urls",
        "domain": "domains",
        "ip": "ip_addresses",
    }.get(kind)
    if not endpoint_type:
        return _result("VirusTotal", indicator, kind, "unsupported")
    # URL lookups require VT's URL identifier; submit/analysis is intentionally not performed here.
    if kind == "url":
        return _result(
            "VirusTotal",
            indicator,
            kind,
            "unsupported",
            errors=[
                "URL lookup requires a submitted VirusTotal URL analysis and is not performed automatically."
            ],
        )
    try:
        body = _request(
            f"https://www.virustotal.com/api/v3/{endpoint_type}/{quote(indicator, safe='')}",
            {"x-apikey": settings.VT_API_KEY, "Accept": "application/json"},
        )
        attributes = body.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        return _result(
            "VirusTotal",
            indicator,
            kind,
            "success",
            {
                "detections": stats,
                "reputation": attributes.get("reputation"),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "provider_attribution": "VirusTotal",
            },
        )
    except Exception as exc:
        return _error("VirusTotal", indicator, kind, exc)


def abuseipdb(indicator, kind):
    if kind != "ip":
        return _result("AbuseIPDB", indicator, kind, "unsupported")
    if not settings.ABUSEIPDB_API_KEY:
        return _result("AbuseIPDB", indicator, kind, "not_configured")
    try:
        data = _request(
            "https://api.abuseipdb.com/api/v2/check?ipAddress=" + quote(indicator),
            {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
        )
        observed = data.get("data", {})
        allowed = {
            x: observed.get(x)
            for x in (
                "abuseConfidenceScore",
                "totalReports",
                "lastReportedAt",
                "isp",
                "domain",
                "countryCode",
                "usageType",
                "isPublic",
            )
        }
        return _result(
            "AbuseIPDB",
            indicator,
            kind,
            "success",
            {
                "report": allowed,
                "provider_attribution": "AbuseIPDB; provider reputation is not a verdict.",
            },
        )
    except Exception as exc:
        return _error("AbuseIPDB", indicator, kind, exc)


def otx(indicator, kind):
    if not settings.OTX_API_KEY:
        return _result("AlienVault OTX", indicator, kind, "not_configured")
    import ipaddress
    endpoint = {"ip": "IPv6" if kind=="ip" and ipaddress.ip_address(indicator).version==6 else "IPv4", "domain": "domain", "hash": "file"}.get(kind)
    if not endpoint:
        return _result("AlienVault OTX", indicator, kind, "unsupported")
    try:
        body = _request(
            f"https://otx.alienvault.com/api/v1/indicators/{endpoint}/{quote(indicator, safe='')}/general",
            {"X-OTX-API-KEY": settings.OTX_API_KEY, "Accept": "application/json"},
        )
        pulse_info = body.get("pulse_info", {})
        return _result(
            "AlienVault OTX",
            indicator,
            kind,
            "success",
            {
                "pulse_count": pulse_info.get("count"),
                "pulses": [
                    {
                        "name": x.get("name"),
                        "created": x.get("created"),
                        "modified": x.get("modified"),
                    }
                    for x in pulse_info.get("pulses", [])[:25]
                ],
                "provider_attribution": "AlienVault OTX",
            },
        )
    except Exception as exc:
        return _error("AlienVault OTX", indicator, kind, exc)


def hibp_email_lookup(email):
    if not settings.HIBP_EMAIL_CHECK_ENABLED:
        return _result("HIBP", email, "email", "disabled")
    if not settings.HIBP_API_KEY:
        return _result("HIBP", email, "email", "not_configured")
    try:
        request = Request(
            "https://haveibeenpwned.com/api/v3/breachedaccount/"
            + quote(email, safe="@"),
            headers={
                "hibp-api-key": settings.HIBP_API_KEY,
                "user-agent": "VigilantSphere security analysis",
                "Accept": "application/json",
            },
        )
        with urlopen(request, timeout=settings.HIBP_EMAIL_TIMEOUT) as response:
            breaches = json.loads(
                response.read(1024 * 1024).decode("utf-8", errors="replace")
            )
        safe = [
            {
                k: b.get(k)
                for k in (
                    "Name",
                    "Title",
                    "BreachDate",
                    "AddedDate",
                    "DataClasses",
                    "IsVerified",
                    "IsSensitive",
                    "IsSpamList",
                    "IsMalware",
                )
            }
            for b in breaches
            if isinstance(b, dict)
        ]
        return _result(
            "HIBP",
            email,
            "email",
            "found" if safe else "not_found",
            {
                "breaches": safe,
                "message": "Found in known breach records"
                if safe
                else "No matching breaches found in the HIBP dataset checked.",
            },
        )
    except HTTPError as exc:
        if exc.code == 404:
            return _result(
                "HIBP",
                email,
                "email",
                "not_found",
                {
                    "breaches": [],
                    "message": "No matching breaches found in the HIBP dataset checked.",
                },
            )
        return _error("HIBP", email, "email", exc)
    except Exception as exc:
        return _error("HIBP", email, "email", exc)


def provider_results(indicator, kind):
    results = [
        virustotal(indicator, kind),
        abuseipdb(indicator, kind),
        otx(indicator, kind),
    ]
    if kind == "email":
        results.append(hibp_email_lookup(indicator))
    return results
