"""Explainable URL lexical observations, independent of network availability."""

import re
import unicodedata
from difflib import SequenceMatcher
from urllib.parse import urlsplit, unquote


def lexical(url):
    host = urlsplit(url).hostname or ""
    try:
        unicode_host = host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        unicode_host = host
    scripts = {
        unicodedata.name(c, "").split(" ")[0] for c in unicode_host if c.isalpha()
    }
    rows = []

    def add(name, evidence, severity="LOW", confidence="low"):
        rows.append(
            {
                "title": name,
                "severity": severity,
                "confidence": confidence,
                "category": "URL lexical indicator",
                "evidence": evidence,
                "description": "Potential indicator only; legitimate URLs may share this characteristic.",
                "source": "local URL analysis",
                "recommendation": "Verify the exact domain and intended destination through a trusted channel.",
            }
        )

    if "xn--" in host:
        add("Internationalized hostname", {"ascii": host, "unicode": unicode_host})
    if len(scripts & {"LATIN", "CYRILLIC", "GREEK"}) > 1:
        add(
            "Potential mixed-script homograph",
            {"hostname": unicode_host, "scripts": sorted(scripts)},
            "MEDIUM",
            "medium",
        )
    keywords = sorted(
        set(
            re.findall(
                r"\b(?:login|verify|password|account|urgent|suspend|billing|secure)\b",
                unquote(url).lower(),
            )
        )
    )
    if keywords:
        add("Credential-related URL words", keywords, "INFO")
    # Compare labels only; this small local reference set is not a domain ownership registry.
    for label in host.split("."):
        for reference in ("google", "microsoft", "paypal", "apple", "amazon"):
            if (
                label != reference
                and len(label) >= 5
                and SequenceMatcher(None, label, reference).ratio() >= 0.8
            ):
                add(
                    "Potential brand-like hostname spelling",
                    {"label": label, "resembles": reference},
                    "LOW",
                )
    return rows
