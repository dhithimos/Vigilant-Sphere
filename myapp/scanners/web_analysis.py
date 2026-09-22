"""Static web indicators are observations, never a phishing or malware verdict."""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

PATTERNS = {
    "eval call": r"\beval\s*\(",
    "dynamic Function": r"\bFunction\s*\(",
    "document.write": r"document\.write\s*\(",
    "base64 decoding": r"\batob\s*\(",
    "character decoding": r"fromCharCode\s*\(",
    "unescape": r"\bunescape\s*\(",
    "location change": r"(?:window\.)?location(?:\.href)?\s*=",
    "window.open": r"window\.open\s*\(",
    "dynamic element": r"createElement\s*\(",
    "long encoded string": r"[A-Za-z0-9+/]{150,}={0,2}",
}


def javascript(text):
    return [
        {
            "indicator": name,
            "state": "Potential Indicator",
            "severity": "LOW",
            "evidence": re.search(pattern, text).group()[:120],
            "count": len(re.findall(pattern, text)),
            "confidence": "low",
            "explanation": "Static syntax observation; legitimate applications can use this construct.",
        }
        for name, pattern in PATTERNS.items()
        if re.search(pattern, text)
    ]


class Document(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.scripts = []
        self.resources = []
        self.links = []
        self.iframes = []
        self.refresh = []
        self.hidden = 0
        self.inline = []
        self.active_script = False
        self.passwords = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.forms.append(
                {
                    "action": a.get("action", ""),
                    "method": a.get("method", "get"),
                    "password_fields": 0,
                }
            )
        if tag == "input" and a.get("type", "").lower() == "password":
            self.passwords += 1
            if self.forms:
                self.forms[-1]["password_fields"] += 1
        if tag == "script":
            self.active_script = True
            if a.get("src"):
                self.scripts.append(a["src"])
        if tag == "iframe":
            self.iframes.append(a.get("src", ""))
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag in {"img", "link", "video", "audio"}:
            self.resources.append(a.get("src", a.get("href", "")))
        if tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.refresh.append(a.get("content", ""))
        if "hidden" in a or a.get("type") == "hidden":
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag == "script":
            self.active_script = False

    def handle_data(self, data):
        if self.active_script:
            self.inline.append(data)


def analyze_html(text, url="https://unknown.invalid/"):
    d = Document()
    d.feed(text)
    host = urlsplit(url).hostname
    external = lambda x: urlsplit(urljoin(url, x)).hostname != host
    return {
        "forms": d.forms,
        "password_fields": d.passwords,
        "external_scripts": [urljoin(url, x) for x in d.scripts if external(x)][:100],
        "external_resources": [urljoin(url, x) for x in d.resources if external(x)][
            :100
        ],
        "external_links": [urljoin(url, x) for x in d.links if external(x)][:200],
        "iframes": d.iframes[:100],
        "meta_refresh": d.refresh[:100],
        "hidden_elements": d.hidden,
        "javascript_indicators": javascript("\n".join(d.inline)),
        "limitation": "Static HTML only. No JavaScript executed or external scripts downloaded.",
    }
