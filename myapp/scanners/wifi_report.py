"""Executive presentation of collected metadata, never simulated radio observations."""

from collections import Counter
from .wifi import MISSING


def executive_report(state, profiles, current):
    profiles = profiles if state == "AVAILABLE" else []
    observed = current.get("status") == "Observed" and current.get("ssid") not in {
        None,
        "",
        MISSING,
    }
    access_points = []
    if observed:
        row = next(
            (
                p
                for p in profiles
                if p.get("ssid") == current["ssid"]
                or p.get("profile_name") == current.get("profile_name")
            ),
            {},
        )
        signal = current.get("signal", MISSING)
        unit = current.get("signal_unit", MISSING)
        category = "Unknown"
        try:
            value = float(str(signal).rstrip("%"))
            if unit == "percent":
                category = (
                    "Strong" if value >= 75 else "Moderate" if value >= 40 else "Weak"
                )
            elif unit == "dBm":
                category = (
                    "Strong" if value >= -60 else "Moderate" if value >= -75 else "Weak"
                )
        except (ValueError, TypeError):
            pass
        access_points.append(
            dict(
                ssid=current["ssid"],
                bssid=current.get("bssid", MISSING),
                security=row.get("authentication") or "Unknown",
                signal=signal,
                signal_unit=unit,
                signal_category=category,
                channel=current.get("channel", MISSING),
                frequency_band=current.get("band", MISSING),
                vendor_oui="Source Unavailable",
                fingerprint={
                    "bssid": current.get("bssid", MISSING),
                    "security": row.get("security_level", "Unknown"),
                },
                pmkid="Not Available — no handshake capture performed",
                handshake="Not Available — no capture evidence",
            )
        )
    findings = []
    for row in profiles:
        if row.get("risk_level") in {"HIGH", "CRITICAL", "MEDIUM"}:
            findings.append(
                dict(
                    title="Saved profile security configuration",
                    severity=row["risk_level"],
                    evidence={
                        "profile": row["profile_name"],
                        "security": row["security_level"],
                        "score_breakdown": row.get("score_breakdown", []),
                    },
                    recommendation=row["recommendation"],
                )
            )
        if row.get("duplicate_ssid_conflict"):
            findings.append(
                dict(
                    title="Potential Rogue AP Indicator",
                    severity="INFO",
                    evidence={
                        "profile": row["profile_name"],
                        "reported_security_modes": row.get("conflicting_levels", []),
                    },
                    recommendation="Saved profiles differ; validate against an approved baseline. This is not proof of a rogue AP or Evil Twin.",
                )
            )
    measured = [p["risk_score"] for p in profiles if p.get("risk_level") != "UNKNOWN"]
    return dict(
        scanner="wifi_security_audit",
        audit_summary={
            "total_networks_discovered": len(access_points),
            "saved_profiles_reviewed": len(profiles),
            "overall_status": "Observed connection metadata"
            if access_points
            else "No scan data available",
            "data_source": "local_wifi_interface",
            "risk_score": max(measured) if measured else None,
            "risk_scope": "Maximum assessed saved-profile configuration score, not radio attack probability",
            "limitations": [
                "Saved profiles are not discovered access points",
                "Only the current reported connection is represented; no neighboring radio survey",
                "Channel congestion, overlap, OUI, PMKID and handshake exposure are not established by this metadata",
            ],
        },
        access_points=access_points,
        signal_summary=[
            {
                "signal": p["signal"],
                "unit": p["signal_unit"],
                "category": p["signal_category"],
            }
            for p in access_points
        ],
        channel_congestion={
            "state": "Insufficient Evidence",
            "reason": "A current connection alone cannot establish channel utilization or overlapping APs",
        },
        frequency_distribution=dict(
            Counter(p["frequency_band"] for p in access_points)
        ),
        security_protocol_distribution=dict(
            Counter(p["security"] for p in access_points)
        ),
        severity_breakdown=dict(Counter(f["severity"] for f in findings)),
        findings=findings,
        evidence={"collection_state": state},
        recommendations=list(dict.fromkeys(f["recommendation"] for f in findings)),
    )
