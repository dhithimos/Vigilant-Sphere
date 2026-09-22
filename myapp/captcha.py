"""
CAPTCHA verification for login/register (Vigilant Sphere).

Supports Cloudflare Turnstile (default) or Google reCAPTCHA v2/v3 via
environment variables. No secret key is ever placed in a template or in
JavaScript - only the public site key reaches the browser.

Environment variables:
    CAPTCHA_PROVIDER    "turnstile" (default) or "recaptcha"
    CAPTCHA_SITE_KEY    public key, safe to render in the page
    CAPTCHA_SECRET_KEY  private key, used only in this server-side module

If CAPTCHA_SITE_KEY / CAPTCHA_SECRET_KEY are not set, captcha_configured()
returns False. Views must then honestly render a "development mode - CAPTCHA
disabled" notice rather than pretending a CAPTCHA widget is protecting the
form. This module never fabricates a "verified" result when it hasn't
actually contacted the provider.
"""

import json
import urllib.parse
import urllib.request

from django.conf import settings

PROVIDER_ENDPOINTS = {
    "turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    "recaptcha": "https://www.google.com/recaptcha/api/siteverify",
}

PROVIDER_FIELD_NAMES = {
    "turnstile": "cf-turnstile-response",
    "recaptcha": "g-recaptcha-response",
}


def captcha_provider():
    return getattr(settings, "CAPTCHA_PROVIDER", "turnstile")


def captcha_site_key():
    return getattr(settings, "CAPTCHA_SITE_KEY", "")


def captcha_configured():
    """True only when both a site key and a secret key are actually set."""
    return bool(captcha_site_key()) and bool(
        getattr(settings, "CAPTCHA_SECRET_KEY", "")
    )


def captcha_field_name():
    return PROVIDER_FIELD_NAMES.get(captcha_provider(), "cf-turnstile-response")


def verify_captcha(request):
    """
    Verify the CAPTCHA response submitted with a POST request.

    Returns (ok, reason):
      ok=True, reason="not_configured" -> CAPTCHA is not set up (dev mode).
          Callers decide whether to allow the request through; this module
          never claims a real verification happened when it did not.
      ok=True, reason="verified"       -> provider confirmed the token.
      ok=False, reason=<code>          -> verification failed or was skipped
          because no token was submitted, the provider was unreachable, or
          the provider rejected it. Callers should block authentication.
    """
    if not captcha_configured():
        return True, "not_configured"

    token = request.POST.get(captcha_field_name(), "").strip()
    if not token:
        return False, "missing_token"

    endpoint = PROVIDER_ENDPOINTS.get(captcha_provider())
    if not endpoint:
        return False, "unknown_provider"

    payload = urllib.parse.urlencode(
        {
            "secret": settings.CAPTCHA_SECRET_KEY,
            "response": token,
            "remoteip": request.META.get("REMOTE_ADDR", ""),
        }
    ).encode("utf-8")

    try:
        req = urllib.request.Request(endpoint, data=payload, method="POST")
        with urllib.request.urlopen(req, timeout=6) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except Exception:
        # Provider unreachable/timeout - fail closed. We never pretend a
        # verification succeeded when we couldn't actually reach the API.
        return False, "provider_unavailable"

    if body.get("success"):
        return True, "verified"
    return False, "rejected"
