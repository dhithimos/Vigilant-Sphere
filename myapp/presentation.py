"""Display-only capability labels. Persisted observations remain unchanged."""

import copy
import re
from django.db.models import Model, QuerySet
from django.http import JsonResponse as DjangoJsonResponse
from django.shortcuts import render as django_render
from django.utils.functional import LazyObject, empty

LABELS = {
    "virustotal": "Reputation Check",
    "abuseipdb": "Network Indicator Lookup",
    "alienvault otx": "Threat Intelligence Correlation",
    "alienvault": "Threat Intelligence Correlation",
    "otx": "Threat Intelligence Correlation",
    "have i been pwned": "Breach Database Check",
    "hibp": "Breach Database Check",
    "pwned passwords": "Breach Database Check",
    "yara": "Local Rule Analysis",
    "clamav": "Local Signature Analysis",
    "clamscan": "Local Signature Analysis",
}
PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    + "|".join(re.escape(k) for k in sorted(LABELS, key=len, reverse=True))
    + r")(?![A-Za-z0-9])",
    re.I,
)


def display_text(value):
    return PATTERN.sub(lambda match: LABELS[match.group().lower()], str(value))


def display(value):
    if isinstance(value, LazyObject):
        if value._wrapped is empty:
            value._setup()
        return display(value._wrapped)
    if isinstance(value, str):
        return display_text(value)
    if isinstance(value, dict):
        result = {
            {"yara": "local_rule_analysis", "clamav": "local_signature_analysis"}.get(
                k, display_text(k)
            ): display(v)
            for k, v in value.items()
        }
        for key in ("provider", "provider_attribution"):
            if key in value:
                raw = str(value[key])
                label = display_text(raw)
                if label == raw and raw not in LABELS.values():
                    label = "External intelligence"
                    if raw:
                        pattern = re.compile(re.escape(raw), re.I)

                        def replace_unknown(item):
                            if isinstance(item, str):
                                return pattern.sub(label, item)
                            if isinstance(item, dict):
                                return {k: replace_unknown(v) for k, v in item.items()}
                            if isinstance(item, list):
                                return [replace_unknown(v) for v in item]
                            return item

                        result = replace_unknown(result)
                result[key] = label
        return result
    if isinstance(value, (list, tuple, QuerySet)):
        return [display(x) for x in value]
    if isinstance(value, Model):
        clone = copy.copy(value)
        clone.__dict__ = {
            k: display(v) if not k.startswith("_") else v
            for k, v in value.__dict__.items()
        }
        return clone
    return value


def render(request, template_name, context=None, *args, **kwargs):
    return django_render(
        request, template_name, display(context or {}), *args, **kwargs
    )


class JsonResponse(DjangoJsonResponse):
    def __init__(self, data, *args, **kwargs):
        super().__init__(display(data), *args, **kwargs)


class CapabilityDisplayMiddleware:
    """Last-mile guard for dynamic/admin HTML and textual exports, including new views."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        content_type = response.get("Content-Type", "")
        if not response.streaming and any(
            t in content_type
            for t in ("text/html", "text/csv", "application/json", "text/plain")
        ):
            original = response.content
            response.content = display_text(original.decode(response.charset)).encode(
                response.charset
            )
            if response.content != original:
                response.headers.pop("ETag", None)
                if "Content-Length" in response:
                    response["Content-Length"] = str(len(response.content))
        return response
