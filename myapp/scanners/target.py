"""Target classification and SSRF-safe, passive web/infrastructure analysis."""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
import socket
import ssl
from urllib.parse import urljoin, urlsplit, urlunsplit

from django.conf import settings

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I
)


def module_result(
    module,
    target,
    target_type,
    status="success",
    data=None,
    findings=None,
    errors=None,
    source="local",
):
    return {
        "module": module,
        "target": target,
        "target_type": target_type,
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": status,
        "source": source,
        "data": data or {},
        "findings": findings or [],
        "errors": errors or [],
    }


def classify_target(value: str) -> tuple[str, str]:
    value = (value or "").strip()
    if not value:
        raise ValueError("Enter a URL, domain, IP address, hash, or email address.")
    if len(value) > 2048:
        raise ValueError("The target exceeds the 2048-character limit.")
    if EMAIL_RE.fullmatch(value):
        return "email", value.lower()
    if len(value) in HASH_LENGTHS and re.fullmatch(r"[0-9a-fA-F]+", value):
        return "hash", value.lower()
    try:
        return "ip", ipaddress.ip_address(value.strip("[]")).compressed
    except ValueError:
        pass
    candidate = value if "://" in value else "https://" + value
    parsed = urlsplit(candidate)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        # Explicit scheme, path/query, auth, or port means URL. Bare host becomes domain.
        if (
            "://" in value
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.port
            or parsed.username
        ):
            return "url", normalize_url(value)
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if DOMAIN_RE.fullmatch(host):
            return "domain", host
    if DOMAIN_RE.fullmatch(value.rstrip(".")):
        return "domain", value.lower().rstrip(".")
    raise ValueError(
        "Target is not a valid URL, domain, IPv4/IPv6 address, hash, or email address."
    )


def normalize_url(value: str) -> str:
    raw = value.strip()
    if "://" not in raw:
        raw = "https://" + raw
    p = urlsplit(raw)
    if p.scheme.lower() not in {"http", "https"} or not p.hostname:
        raise ValueError("Only complete HTTP(S) URLs are supported.")
    if any(c.isspace() or ord(c) < 32 for c in raw) or p.username is not None:
        raise ValueError("Blocked URL whitespace, controls or embedded credentials.")
    if p.port and p.port not in {80, 443}:
        raise ValueError("Blocked nonstandard port.")
    host = p.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if ":" in host:
        host = "[" + host + "]"
    authority = host + (":" + str(p.port) if p.port else "")
    return urlunsplit((p.scheme.lower(), authority, p.path or "/", p.query, ""))


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def safe_host(host: str) -> list[str]:
    """Resolve and validate every destination. Reject mixed/numeric private forms too."""
    if not host or host.lower().rstrip(".") in {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
    }:
        raise ValueError("Blocked internal or metadata hostname.")
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
        if not _public_ip(str(literal)):
            raise ValueError("Blocked non-public IP address.")
        return [str(literal)]
    except ValueError as exc:
        if "Blocked" in str(exc):
            raise
    try:
        answers = sorted(
            {
                row[4][0]
                for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            }
        )
    except socket.gaierror as exc:
        raise ValueError(f"DNS lookup failed: {exc.__class__.__name__}") from exc
    if not answers or any(not _public_ip(ip) for ip in answers):
        raise ValueError(
            "Blocked hostname because it resolves to a non-public address."
        )
    return answers


def url_details(url: str) -> dict:
    p = urlsplit(url)
    return {
        "ip_based": bool(p.hostname and re.fullmatch(r"[0-9.:]+", p.hostname)),
        "unicode_hostname": p.hostname.encode("ascii").decode("idna")
        if p.hostname
        else "",
        "subdomain_count": max(0, len((p.hostname or "").split(".")) - 2),
        "hostname_length": len(p.hostname or ""),
        "encoded_parameter_count": p.query.count("%"),
        "shortener_indicator": p.hostname in {"bit.ly", "t.co", "tinyurl.com", "is.gd"},
        "assessment": "Lexical observations only; none establishes phishing.",
        "original_url": url,
        "normalized_url": normalize_url(url),
        "scheme": p.scheme,
        "hostname": p.hostname,
        "punycode_hostname": p.hostname.encode("idna").decode("ascii")
        if p.hostname
        else "",
        "port": p.port or (443 if p.scheme == "https" else 80),
        "path": p.path,
        "query_parameter_count": len([x for x in p.query.split("&") if x]),
        "fragment": p.fragment,
        "username_present": p.username is not None,
        "password_present": p.password is not None,
        "length": len(url),
    }


def http_scan(url: str) -> list[dict]:
    from .transport import fetch
    from .web_analysis import analyze_html

    target = normalize_url(url)
    details = url_details(target)
    from .phishing_indicators import lexical

    lexical_result = module_result(
        "url_details", target, "url", data=details, findings=lexical(target)
    )
    try:
        observed = fetch(target)
    except ValueError as exc:
        return [
            lexical_result,
            module_result("http", target, "url", "blocked", errors=[str(exc)]),
        ]
    except (
        OSError,
        ssl.SSLError,
        __import__("http.client", fromlist=["HTTPException"]).HTTPException,
    ):
        return [
            lexical_result,
            module_result(
                "http",
                target,
                "url",
                "unavailable",
                errors=["Network Unavailable: HTTP request could not be completed."],
            ),
        ]
    headers = observed["headers"]
    html = (
        analyze_html(
            observed["body"].decode("utf-8", errors="replace"), observed["url"]
        )
        if "html" in headers.get("content-type", "")
        else {"state": "Not Applicable"}
    )
    findings = []

    def add(title, severity, evidence, remediation):
        findings.append(
            {
                "title": title,
                "severity": severity,
                "confidence": "medium",
                "category": "Web observation",
                "description": "Observed indicator; requires context. Not a phishing verdict.",
                "evidence": evidence,
                "source": "local HTTP",
                "recommendation": remediation,
            }
        )

    states = {
        h: ("Observed" if h in headers else "Not Observed")
        for h in [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ]
    }
    if (
        urlsplit(observed["url"]).scheme == "https"
        and "strict-transport-security" not in headers
    ):
        add(
            "HSTS not observed",
            "LOW",
            "Header absent in received response",
            "Review HTTPS-only policy.",
        )
    if "content-security-policy" not in headers:
        add(
            "CSP not observed",
            "LOW",
            "Header absent in received response",
            "Review Content Security Policy.",
        )
    for form in html.get("forms", []):
        action = urljoin(observed["url"], form["action"])
        if form["password_fields"] and urlsplit(action).scheme == "http":
            add(
                "Password form uses HTTP",
                "HIGH",
                {"action": action},
                "Use HTTPS for credential submission.",
            )
        if (
            form["password_fields"]
            and urlsplit(action).hostname != urlsplit(observed["url"]).hostname
        ):
            add(
                "Cross-domain password form",
                "MEDIUM",
                {"action": action},
                "Verify the authentication provider and intended destination.",
            )
    cookies = []
    for raw in observed.pop("cookies"):
        parts = [x.strip() for x in raw.split(";")]
        attrs = {
            x.split("=", 1)[0].lower(): x.split("=", 1)[1] if "=" in x else True
            for x in parts[1:]
        }
        cookies.append(
            {
                "name": parts[0].split("=", 1)[0],
                "secure": "secure" in attrs,
                "httponly": "httponly" in attrs,
                "samesite": attrs.get("samesite", "Not Observed"),
            }
        )
    headers.pop("set-cookie", None)
    observed.pop("body")
    observed["cookies"] = cookies
    return [
        lexical_result,
        module_result("http", target, "url", data=observed),
        module_result("headers", target, "url", data=states, findings=findings),
        module_result("html", target, "url", data=html),
        module_result(
            "javascript",
            target,
            "url",
            data={
                "indicators": html.get("javascript_indicators", []),
                "state": "Static Analysis",
            },
        ),
    ]


def dns_scan(domain: str, target_type="domain") -> dict:
    import dns.resolver
    import dns.reversename

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    resolver.timeout = 2
    data = {}
    for kind in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "PTR"):
        try:
            query = (
                dns.reversename.from_address(domain)
                if kind == "PTR" and target_type == "ip"
                else domain
            )
            answers = resolver.resolve(query, kind)
            data[kind] = {
                "state": "Observed",
                "records": [str(x) for x in answers][:100],
            }
        except dns.resolver.NXDOMAIN:
            data[kind] = {"state": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            data[kind] = {"state": "Not Observed"}
        except Exception:
            data[kind] = {
                "state": "Unavailable",
                "detail": "Network Unavailable or resolver failure",
            }
    state = (
        "unavailable"
        if all(v["state"] == "Unavailable" for v in data.values())
        else "success"
    )
    return module_result("dns", domain, target_type, state, data=data)


def tls_scan(host: str, port=443, target_type="domain") -> dict:
    try:
        ips = safe_host(host)
        if port not in {80, 443}:
            raise ValueError("Blocked port")
        context = ssl.create_default_context()
        with socket.create_connection(
            (ips[0], port), timeout=settings.TARGET_HTTP_TIMEOUT
        ) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure:
                cert = secure.getpeercert()
                return module_result(
                    "tls",
                    host,
                    target_type,
                    data={
                        "verification_state": "Observed: certificate chain and hostname verified",
                        "protocol": secure.version(),
                        "cipher": secure.cipher()[0] if secure.cipher() else None,
                        "subject": cert.get("subject", []),
                        "issuer": cert.get("issuer", []),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "serial_number": cert.get("serialNumber"),
                        "subject_alt_names": cert.get("subjectAltName", []),
                    },
                )
    except (OSError, ssl.SSLError, ValueError) as exc:
        return module_result(
            "tls",
            host,
            target_type,
            "error",
            errors=[f"TLS check failed: {exc.__class__.__name__}"],
        )


def rdap_scan(domain: str) -> dict:
    """Read public registration events using the same SSRF-safe bounded transport."""
    import json
    from http.client import HTTPException
    from .transport import fetch
    from urllib.parse import quote

    try:
        host = domain.encode("idna").decode("ascii").lower()
        if not DOMAIN_RE.fullmatch(host):
            raise ValueError("Invalid registration domain")
        response = fetch("https://rdap.org/domain/" + quote(host, safe=""))
        if response["status"] != 200 or response["truncated"]:
            raise ValueError("Registration response unavailable or incomplete")
        document = json.loads(response["body"])
        events = [
            {"action": e.get("eventAction"), "date": e.get("eventDate")}
            for e in document.get("events", [])[:100]
            if isinstance(e, dict)
        ]
        registration = next(
            (e["date"] for e in events if e["action"] == "registration"), None
        )
        age = None
        if registration:
            registered = dt.datetime.fromisoformat(registration.replace("Z", "+00:00"))
            if registered.tzinfo:
                age = (dt.datetime.now(dt.timezone.utc) - registered).days
                if age < 0:
                    age = None
        return module_result(
            "registration",
            domain,
            "domain",
            data={
                "state": "Observed",
                "queried_domain": host,
                "events": events,
                "registration_date": registration,
                "age_days": age,
                "age_state": "Observed" if age is not None else "Unavailable",
                "limitation": "Registration is not domain ownership or reputation proof. Subdomain queries may have no registration record; no guessed parent domain is queried.",
            },
        )
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        OverflowError,
        HTTPException,
    ):
        return module_result(
            "registration",
            domain,
            "domain",
            "unavailable",
            data={"state": "Unavailable", "age_state": "Unavailable"},
            errors=[
                "Registration data could not be retrieved or parsed. No age inference made."
            ],
        )
