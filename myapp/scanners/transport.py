"""Bounded public HTTP transport. DNS is resolved once and sockets use validated IPs."""

import http.client
import socket
import time
import ssl
from urllib.parse import urlsplit, urljoin
from django.conf import settings


def fetch(url):
    from .target import normalize_url, safe_host

    current = normalize_url(url)
    chain = []
    for step in range(settings.TARGET_REDIRECT_LIMIT + 1):
        p = urlsplit(current)
        port = p.port or (443 if p.scheme == "https" else 80)
        if p.username is not None or port not in {80, 443}:
            raise ValueError("Blocked URL credentials or nonstandard port.")
        ips = safe_host(p.hostname)
        conn = http.client.HTTPConnection(
            p.hostname, port, timeout=settings.TARGET_HTTP_TIMEOUT
        )
        try:
            conn.sock = socket.create_connection(
                (ips[0], port), settings.TARGET_HTTP_TIMEOUT
            )
            if p.scheme == "https":
                conn.sock = ssl.create_default_context().wrap_socket(
                    conn.sock, server_hostname=p.hostname
                )
            conn.request(
                "GET",
                p.path + ("?" + p.query if p.query else ""),
                headers={
                    "Host": p.netloc,
                    "User-Agent": "VigilantSphere/2 passive analysis",
                    "Accept-Encoding": "identity",
                },
            )
            response = conn.getresponse()
            pairs = response.getheaders()
            headers = {k.lower(): v for k, v in pairs}
            location = headers.get("location")
            if response.status in {301, 302, 303, 307, 308} and location:
                if step == settings.TARGET_REDIRECT_LIMIT:
                    raise ValueError("Redirect limit exceeded.")
                nxt = normalize_url(urljoin(current, location))
                chain.append(
                    {"url": current, "status_code": response.status, "location": nxt}
                )
                current = nxt
                continue
            deadline = time.monotonic() + settings.TARGET_HTTP_TIMEOUT
            chunks = []
            remaining = settings.TARGET_HTTP_MAX_BYTES + 1
            while remaining > 0:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Response read deadline exceeded")
                chunk = response.read1(min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            body = b"".join(chunks)
            return {
                "url": current,
                "status": response.status,
                "headers": headers,
                "cookies": [v for k, v in pairs if k.lower() == "set-cookie"],
                "body": body[: settings.TARGET_HTTP_MAX_BYTES],
                "truncated": len(body) > settings.TARGET_HTTP_MAX_BYTES,
                "redirects": chain,
                "serving_ips": [ips[0]],
            }
        finally:
            conn.close()
    raise ValueError("Redirect limit exceeded.")
