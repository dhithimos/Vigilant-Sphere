"""Bounded local authentication throttling; deployment scale needs shared cache."""

import hashlib
from django.core.cache import cache
from django.http import HttpResponse


class AuthenticationThrottle:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == "POST" and request.path in {
            "/login/",
            "/register/",
            "/forgot-password/",
        }:
            identity = request.META.get("REMOTE_ADDR", "unknown")
            key = (
                "auth-limit:"
                + hashlib.sha256((identity + request.path).encode()).hexdigest()
            )
            attempts = cache.get(key, 0)
            if attempts >= 20:
                return HttpResponse(
                    "Rate Limited. Try again in 15 minutes.", status=429
                )
            cache.set(key, attempts + 1, 900)
        return self.get_response(request)
