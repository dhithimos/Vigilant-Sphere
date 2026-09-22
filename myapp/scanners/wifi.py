"""Passive local metadata collection. No key fields or secret CLI options are requested."""

import platform
import re
import subprocess

MISSING = "Not reported by OS"
AIRPORT = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"


def classify(authentication, encryption, auto_connect=None):
    auth, enc = (authentication or "").upper(), (encryption or "").upper()
    level, score = "UNKNOWN", 0
    if "WEP" in auth or "WEP" in enc:
        level, score = "WEP", 95
    elif auth in {"OPEN", "NONE"}:
        level, score = "OPEN", 70
    elif "OWE" in auth:
        level, score = "OWE", 20
    elif "ENTERPRISE" in auth:
        level, score = "ENTERPRISE", 0
    elif "WPA3" in auth:
        level, score = "WPA3", 10
    elif "WPA2" in auth and "TKIP" in enc:
        level, score = "WPA2-TKIP", 40
    elif "WPA2" in auth and any(x in enc for x in ("CCMP", "AES", "GCMP")):
        level, score = "WPA2", 15
    elif "WPA2" in auth:
        level, score = "UNKNOWN", 0
    elif "WPA" in auth:
        level, score = "WPA", 70
    breakdown = [
        {
            "label": level + " configuration" if level != "UNKNOWN" else MISSING,
            "points": score,
        }
    ]
    reason = (
        "Saved profile reports " + level + " configuration."
        if level not in {"UNKNOWN", "ENTERPRISE"}
        else MISSING
    )
    if auto_connect is True and level in {"OPEN", "WEP"}:
        score += 15
        breakdown.append({"label": "Auto-connect on open/WEP network", "points": 15})
        reason += " The profile auto-connects to an open/WEP network."
    if score > 100:
        breakdown.append({"label": "Capped at maximum score", "points": 100 - score})
        score = 100
    risk = (
        "UNKNOWN"
        if level in {"UNKNOWN", "ENTERPRISE"}
        else "CRITICAL"
        if score >= 90
        else "HIGH"
        if score >= 60
        else "MEDIUM"
        if score >= 30
        else "LOW"
    )
    baseline = {
        "OPEN": "Does not meet minimum WPA2 baseline",
        "WEP": "Does not meet minimum WPA2 baseline",
        "WPA": "Does not meet minimum WPA2 baseline",
        "WPA2-TKIP": "Uses WPA2 with deprecated TKIP; below the AES-CCMP baseline expectation",
        "WPA2": "Meets minimum WPA2 baseline",
        "WPA3": "Meets minimum WPA2 baseline",
    }.get(level, "Baseline could not be determined (security type not fully reported)")
    recommendation = "Verify intended configuration and maintain router updates. Prefer WPA3 or WPA2 with AES/CCMP."
    if level == "OPEN":
        recommendation += " Avoid sensitive activity on public Wi-Fi; consider a trusted VPN. No captive portal was probed."
    return dict(
        security_level=level,
        risk_level=risk,
        risk_score=score,
        reason=reason,
        recommendation=recommendation,
        score_breakdown=breakdown,
        baseline_statement=baseline,
        baseline_disclaimer="Informational mapping; not a compliance certification.",
        auto_connect=auto_connect if auto_connect is not None else MISSING,
        wps_status=MISSING,
    )


def _run(args):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
        check=False,
        encoding="utf-8",
        errors="replace",
    )


def fields(output):
    return {
        k.strip().lower(): v.strip()
        for line in output.splitlines()
        if ":" in line
        for k, v in [line.split(":", 1)]
    }


def parse_profiles(output):
    return [row["profile_name"] for row in parse_profile_entries(output)]


def parse_profile_entries(output):
    rows = []
    for line in output.splitlines():
        if ":" in line:
            scope, name = (x.strip() for x in line.split(":", 1))
            if (
                scope in {"All User Profile", "Current User Profile", "User Profile"}
                and name
            ):
                rows.append({"profile_name": name, "scope": scope})
    return rows


def parse_profile_security(output):
    data = fields(output)
    return data.get("authentication", ""), data.get(
        "cipher", data.get("encryption", "")
    )


def parse_profile_connection_mode(output):
    mode = fields(output).get("connection mode", "").lower()
    return (
        True
        if mode == "connect automatically"
        else False
        if mode == "connect manually"
        else None
    )


def split_terse(line):
    result = []
    current = ""
    escaped = False
    for c in line:
        if escaped:
            current += c
            escaped = False
        elif c == "\\":
            escaped = True
        elif c == ":":
            result.append(current)
            current = ""
        else:
            current += c
    result.append(current)
    return result


def band(frequency=None, radio=""):
    try:
        mhz = float(str(frequency).split()[0])
        if 2400 <= mhz <= 2500:
            return "2.4 GHz"
        if 5150 <= mhz < 5925:
            return "5 GHz"
        if 5925 <= mhz <= 7125:
            return "6 GHz"
    except (ValueError, TypeError, IndexError):
        pass
    if radio in {"802.11a", "802.11ac"}:
        return "5 GHz"
    if radio in {"802.11b", "802.11g"}:
        return "2.4 GHz"
    return MISSING


def _row(name, auth="", enc="", auto=None, status="AVAILABLE", **extra):
    return dict(
        profile_name=name,
        authentication=auth,
        encryption=enc,
        collection_status=status,
        **classify(auth, enc, auto),
        **extra,
    )


def _failure(result):
    return (
        "PERMISSION DENIED"
        if re.search(
            r"denied|not authorized|insufficient", result.stderr + result.stdout, re.I
        )
        else "COLLECTION ERROR"
    )


def collect_windows():
    listing = _run(["netsh", "wlan", "show", "profiles"])
    if listing.returncode:
        return _failure(listing), [], "Windows could not list profiles."
    entries = parse_profile_entries(listing.stdout)
    if not entries:
        return (
            "NO SAVED PROFILES",
            [],
            "No profiles parsed; English output is required.",
        )
    rows = []
    for entry in entries[:200]:
        try:
            result = _run(
                ["netsh", "wlan", "show", "profile", "name=" + entry["profile_name"]]
            )
            auth, enc = parse_profile_security(
                result.stdout if result.returncode == 0 else ""
            )
            ssid = fields(result.stdout).get("ssid name", "").strip('"') or MISSING
            rows.append(
                _row(
                    entry["profile_name"],
                    auth,
                    enc,
                    parse_profile_connection_mode(result.stdout),
                    status="AVAILABLE"
                    if result.returncode == 0 and auth and enc
                    else "UNAVAILABLE" if result.returncode == 0
                    else "COLLECTION ERROR",
                    ssid=ssid,
                    scope=entry["scope"],
                )
            )
        except (OSError, subprocess.TimeoutExpired):
            rows.append(
                _row(
                    entry["profile_name"],
                    status="COLLECTION ERROR",
                    ssid=MISSING,
                    scope=entry["scope"],
                )
            )
    return "AVAILABLE", rows, "Saved-profile metadata only; English output required."


def linux_security(km, proto, pairwise):
    if km == "":
        return "Open", "None"
    if km == "sae":
        return "WPA3", pairwise
    if km == "owe":
        return "OWE", pairwise
    if km in {"wpa-eap", "wpa-eap-suite-b-192", "ieee8021x"}:
        return "ENTERPRISE", pairwise
    if km == "wpa-psk":
        return ("WPA" if proto.strip() == "wpa" else "WPA2"), pairwise
    # `none` is insufficient evidence of configured WEP; never read key properties.
    return "UNKNOWN", pairwise


def collect_linux():
    listing = _run(["nmcli", "-t", "-f", "UUID,NAME,TYPE", "connection", "show"])
    if listing.returncode:
        return _failure(listing), [], "NetworkManager collection failed."
    rows = []
    for line in listing.stdout.splitlines()[:200]:
        parts = split_terse(line)
        if (
            len(parts) != 3
            or parts[2] not in {"wifi", "802-11-wireless"}
            or not re.fullmatch(r"[0-9a-fA-F-]{36}", parts[0])
        ):
            continue
        ref, name, _ = parts
        result = _run(
            [
                "nmcli",
                "-g",
                "802-11-wireless-security.key-mgmt,802-11-wireless-security.proto,802-11-wireless-security.pairwise,connection.autoconnect,802-11-wireless.ssid",
                "connection",
                "show",
                "uuid",
                ref,
            ]
        )
        values = result.stdout.splitlines()
        if result.returncode or len(values) < 5:
            rows.append(_row(name, status="COLLECTION ERROR", ssid=MISSING))
            continue
        km, proto, cipher, auto, ssid = values[:5]
        auth, enc = linux_security(km, proto, cipher)
        rows.append(
            _row(
                name,
                auth,
                enc,
                True if auto == "yes" else False if auto == "no" else None,
                ssid=ssid or MISSING,
                scope=ref,
            )
        )
    return (
        ("AVAILABLE", rows, "Saved connection metadata only.")
        if rows
        else ("NO SAVED PROFILES", [], "No wireless profiles reported.")
    )


def mac_interface(output):
    blocks = re.split(r"\n\s*\n", output)
    for block in blocks:
        data = fields(block)
        if data.get("hardware port") in {"Wi-Fi", "AirPort"} and re.fullmatch(
            r"en\d+", data.get("device", "")
        ):
            return data["device"]
    return None


def collect_macos():
    listing = _run(["networksetup", "-listallhardwareports"])
    if listing.returncode:
        return _failure(listing), [], "Hardware ports unavailable."
    iface = mac_interface(listing.stdout)
    if not iface:
        return "COLLECTION ERROR", [], "Wi-Fi interface not reported by OS."
    result = _run(["networksetup", "-listpreferredwirelessnetworks", iface])
    if result.returncode:
        return _failure(result), [], "Preferred networks unavailable."
    names = [line.strip() for line in result.stdout.splitlines()[1:] if line.strip()]
    rows = [_row(name, ssid=name) for name in names[:200]]
    return (
        (
            "AVAILABLE",
            rows,
            "Saved network security and auto-connect are not reported by OS.",
        )
        if rows
        else ("NO SAVED PROFILES", [], "No preferred networks reported.")
    )


def collect():
    try:
        fn = {
            "Windows": collect_windows,
            "Linux": collect_linux,
            "Darwin": collect_macos,
        }.get(platform.system())
        return fn() if fn else ("UNSUPPORTED OS", [], "Not available on this platform")
    except FileNotFoundError:
        return "UNSUPPORTED OS", [], "Required local CLI is not installed."
    except subprocess.TimeoutExpired:
        return "COLLECTION ERROR", [], "Local metadata command timed out."
    except OSError:
        return "COLLECTION ERROR", [], "Local metadata command failed."


def collect_current_connection():
    result = {
        k: MISSING
        for k in (
            "ssid",
            "profile_name",
            "signal",
            "signal_unit",
            "channel",
            "band",
            "bssid",
            "gateway",
            "dns",
        )
    }
    result["status"] = "Unavailable"
    system = platform.system()
    try:
        if system == "Windows":
            run = _run(["netsh", "wlan", "show", "interfaces"])
            data = fields(run.stdout if run.returncode == 0 else "")
            if data.get("state") == "connected":
                result.update(
                    ssid=data.get("ssid", MISSING),
                    profile_name=data.get("profile", MISSING),
                    signal=data.get("signal", MISSING),
                    signal_unit="percent",
                    channel=data.get("channel", MISSING),
                    band=band(radio=data.get("radio type", "")),
                    bssid=data.get("bssid", MISSING),
                    status="Observed",
                )
            net = (
                _run(
                    [
                        "netsh",
                        "interface",
                        "ip",
                        "show",
                        "config",
                        "name=" + data["name"],
                    ]
                )
                if data.get("state") == "connected" and data.get("name")
                else subprocess.CompletedProcess([], 1, "", "")
            )
            data = fields(net.stdout if net.returncode == 0 else "")
            result["gateway"] = data.get("default gateway", MISSING)
            result["dns"] = data.get(
                "dns servers configured through dhcp",
                data.get("statically configured dns servers", MISSING),
            )
        elif system == "Linux":
            run = _run(
                [
                    "nmcli",
                    "-t",
                    "-f",
                    "ACTIVE,SSID,SIGNAL,CHAN,FREQ,BSSID",
                    "device",
                    "wifi",
                    "list",
                    "--rescan",
                    "no",
                ]
            )
            for line in run.stdout.splitlines() if run.returncode == 0 else []:
                p = split_terse(line)
                if len(p) == 6 and p[0] == "yes":
                    result.update(
                        status="Observed",
                        ssid=p[1] or MISSING,
                        signal=p[2] or MISSING,
                        signal_unit="percent",
                        channel=p[3] or MISSING,
                        band=band(p[4]),
                        bssid=p[5] or MISSING,
                    )
                    break
            devices = _run(
                ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status"]
            )
            for line in devices.stdout.splitlines() if devices.returncode == 0 else []:
                device = split_terse(line)
                if (
                    len(device) == 3
                    and device[1] == "wifi"
                    and device[2] == "connected"
                    and re.fullmatch(r"[A-Za-z0-9_.-]+", device[0])
                ):
                    net = _run(
                        [
                            "nmcli",
                            "-t",
                            "-f",
                            "IP4.GATEWAY,IP4.DNS,IP6.GATEWAY,IP6.DNS",
                            "device",
                            "show",
                            device[0],
                        ]
                    )
                    gateways = []
                    dns = []
                    for item in net.stdout.splitlines() if net.returncode == 0 else []:
                        parts = split_terse(item)
                        if len(parts) == 2 and parts[1] and parts[1] != "--":
                            if "GATEWAY" in parts[0]:
                                gateways.append(parts[1])
                            elif "DNS" in parts[0]:
                                dns.append(parts[1])
                    result["gateway"] = ", ".join(dict.fromkeys(gateways)) or MISSING
                    result["dns"] = ", ".join(dict.fromkeys(dns)) or MISSING
                    break
        elif system == "Darwin":
            try:
                run = _run([AIRPORT, "-I"])
            except (OSError, subprocess.TimeoutExpired):
                run = subprocess.CompletedProcess([], 1, "", "")
            data = fields(run.stdout if run.returncode == 0 else "")
            if data.get("ssid"):
                result.update(
                    status="Observed",
                    ssid=data["ssid"],
                    signal=data.get("agrctlrssi", MISSING),
                    signal_unit="dBm",
                    channel=data.get("channel", MISSING),
                    bssid=data.get("bssid", MISSING),
                )
            net = _run(["route", "-n", "get", "default"])
            result["gateway"] = (
                fields(net.stdout).get("gateway", MISSING)
                if net.returncode == 0
                else MISSING
            )
            dns = _run(["scutil", "--dns"])
            addresses = re.findall(
                r"nameserver\[\d+\]\s*:\s*(\S+)",
                dns.stdout if dns.returncode == 0 else "",
            )
            result["dns"] = ", ".join(dict.fromkeys(addresses)) or MISSING
    except (OSError, subprocess.TimeoutExpired):
        pass
    for key in ("gateway", "dns"):
        if "127.0.0.53" in result[key] or "127.0.0.1" in result[key]:
            result[key] += " (local resolver stub; upstream not reported)"
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", result["bssid"]):
        result["bssid"] = MISSING
    return result
