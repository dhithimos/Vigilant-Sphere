"""Configurable SMTP notifications. Credentials are read from environment settings."""

from __future__ import annotations
import re
from html import escape
from django.conf import settings
from django.core.mail import EmailMultiAlternatives, get_connection
from django.utils import timezone
from .models import AlertEmailConfiguration, SecurityAlertDelivery, SecurityAlert
from django.db import transaction
from datetime import timedelta
from .severity import meets, ORDER
from .security_pipeline import redact


def _config():
    saved = AlertEmailConfiguration.objects.order_by("-updated_at").first()
    host = saved.host if saved and saved.host else settings.VIGILANT_SMTP_HOST
    sender = (
        saved.from_email
        if saved and saved.from_email
        else settings.VIGILANT_ALERT_FROM_EMAIL
    )
    recipient_text = (
        saved.recipients
        if saved and saved.recipients
        else settings.VIGILANT_ALERT_RECIPIENTS
    )
    recipients = [
        item.strip()
        for item in re.split(r"[,\n;]+", recipient_text or "")
        if item.strip()
    ]
    return {
        "enabled": bool(saved and saved.enabled),
        "threshold": saved.alert_severity_threshold if saved else "CRITICAL",
        "window": saved.alert_dedup_window_hours if saved else 24,
        "host": host,
        "port": saved.port if saved and saved.host else settings.VIGILANT_SMTP_PORT,
        "tls": saved.use_tls
        if saved and saved.host
        else settings.VIGILANT_SMTP_USE_TLS,
        "ssl": saved.use_ssl
        if saved and saved.host
        else settings.VIGILANT_SMTP_USE_SSL,
        "sender": sender,
        "recipients": recipients,
    }


def _safe(value):
    return escape(str(redact(value)))[:4000]


def send_alert(alert, force=False):
    finding = alert.finding
    if not meets(finding.severity, _config()["threshold"]):
        return None
    delivery, created = SecurityAlertDelivery.objects.get_or_create(alert=alert)
    if delivery.status == "SENT" and not force:
        return delivery
    cfg = _config()
    if (
        not cfg["enabled"]
        or not cfg["host"]
        or not cfg["sender"]
        or not cfg["recipients"]
    ):
        delivery.status, delivery.error = "NOT_CONFIGURED", "EMAIL NOT CONFIGURED"
        delivery.save(update_fields=["status", "error", "updated_at"])
        return delivery
    delivery.delivery_attempts += 1
    try:
        connection = get_connection(
            host=cfg["host"],
            port=cfg["port"],
            username=settings.VIGILANT_SMTP_USERNAME,
            password=settings.VIGILANT_SMTP_PASSWORD,
            use_tls=cfg["tls"],
            use_ssl=cfg["ssl"],
            timeout=10,
        )
        body = f"""<html><body><h1>VIGILANT SPHERE</h1><h2>{_safe(finding.severity)} SECURITY ALERT</h2><table>
<tr><th>Finding</th><td>{_safe(finding.title)}</td></tr><tr><th>Risk score</th><td>{finding.risk_score}</td></tr>
<tr><th>Confidence</th><td>{finding.confidence}</td></tr><tr><th>Scanner</th><td>{_safe(finding.scanner)}</td></tr>
<tr><th>Timestamp</th><td>{finding.timestamp}</td></tr><tr><th>Asset</th><td>{_safe(finding.asset)}</td></tr>
<tr><th>MITRE ATT&amp;CK</th><td>{_safe(finding.mitre_technique)}</td></tr><tr><th>Evidence</th><td><pre>{_safe(finding.evidence)}</pre></td></tr>
<tr><th>Recommendation</th><td>{_safe(finding.recommendation)}</td></tr><tr><th>Required action</th><td>{_safe(finding.remediation)}</td></tr></table></body></html>"""
        mail = EmailMultiAlternatives(
            f"[VIGILANT SPHERE] {finding.severity} Security Finding",
            "Critical security finding detected. Open Vigilant Sphere for redacted evidence.",
            cfg["sender"],
            cfg["recipients"],
            connection=connection,
        )
        mail.attach_alternative(body, "text/html")
        if mail.send(fail_silently=False) == 0:
            raise RuntimeError("No recipients accepted")
        delivery.status, delivery.error, delivery.sent_at, delivery.recipient_count = (
            "SENT",
            "",
            timezone.now(),
            len(cfg["recipients"]),
        )
    except Exception as exc:
        delivery.status, delivery.error = (
            "FAILED",
            f"{type(exc).__name__}: delivery failed"[:500],
        )
    delivery.save()
    if delivery.status == "SENT":
        alert.last_notified_at = delivery.sent_at
        alert.save(update_fields=["last_notified_at"])
    return delivery


def send_critical_alert(alert, force=False):
    """Backward-compatible name; severity is controlled by configuration."""
    return send_alert(alert, force=force)


@transaction.atomic
def get_or_create_deduped_alert(finding, dedup_key=""):
    cfg = _config()
    if not meets(finding.severity, cfg["threshold"]):
        return None
    # Serialize notifier mutations, including first alerts with no prior matching row.
    config, _ = AlertEmailConfiguration.objects.get_or_create(pk=1)
    AlertEmailConfiguration.objects.filter(pk=config.pk).update(
        alert_dedup_window_hours=config.alert_dedup_window_hours
    )
    cutoff = timezone.now() - timedelta(hours=cfg["window"])
    previous = (
        SecurityAlert.objects.select_for_update()
        .filter(dedup_key=dedup_key, last_notified_at__gte=cutoff)
        .select_related("finding")
        .order_by("-last_notified_at")
        .first()
        if dedup_key
        else None
    )
    if previous and ORDER.get(finding.severity, -1) <= ORDER.get(
        previous.finding.severity, -1
    ):
        previous.status = "OPEN"
        previous.save(update_fields=["status"])
        finding.evidence = dict(
            finding.evidence or {}, alert_suppression="deduplicated"
        )
        finding.save(update_fields=["evidence"])
        return previous
    alert, _ = SecurityAlert.objects.get_or_create(
        finding=finding, defaults={"dedup_key": dedup_key}
    )
    send_alert(alert)
    return alert


def delivery_label(finding):
    if not finding:
        return "No alert raised"
    try:
        return finding.alert.email_delivery.get_status_display()
    except (SecurityAlert.DoesNotExist, SecurityAlertDelivery.DoesNotExist):
        return (
            "No alert raised — deduplicated"
            if isinstance(finding.evidence, dict)
            and finding.evidence.get("alert_suppression") == "deduplicated"
            else "No alert raised"
        )


@transaction.atomic
def send_digest(dry_run=False, force=False):
    config, _ = AlertEmailConfiguration.objects.get_or_create(pk=1)
    # A write lock also serializes this operation on SQLite.
    AlertEmailConfiguration.objects.filter(pk=config.pk).update(
        digest_enabled=config.digest_enabled
    )
    config.refresh_from_db()
    cfg = _config()
    now = timezone.now()
    if not config.digest_enabled:
        return "Digest disabled"
    if (
        not cfg["enabled"]
        or not cfg["host"]
        or not cfg["sender"]
        or not cfg["recipients"]
    ):
        return "Email not configured"
    days = 7 if config.digest_frequency == "WEEKLY" else 1
    if (
        not force
        and config.last_digest_sent_at
        and now - config.last_digest_sent_at < timedelta(days=days)
    ):
        return "Digest not due"
    rows = SecurityAlert.objects.filter(created_at__lte=now).select_related("finding")
    if config.last_digest_sent_at:
        rows = rows.filter(created_at__gt=config.last_digest_sent_at)
    alerts = list(rows.order_by("created_at")[:1000])
    if not alerts:
        return "No new alerts"
    boundary = alerts[-1].created_at
    if len(alerts) == 1000:
        alerts.extend(
            rows.filter(created_at=boundary)
            .exclude(pk__in=[a.pk for a in alerts])
            .order_by("pk")
        )
    if dry_run:
        return f"Would summarize {len(alerts)} alerts"
    body = "<h1>Security alert digest</h1>" + "".join(
        f"<h2>{_safe(a.finding.severity)}: {_safe(a.finding.title)}</h2><pre>{_safe(a.finding.evidence)}</pre><p>{_safe(a.finding.recommendation)}</p>"
        for a in alerts
    )
    connection = get_connection(
        host=cfg["host"],
        port=cfg["port"],
        username=settings.VIGILANT_SMTP_USERNAME,
        password=settings.VIGILANT_SMTP_PASSWORD,
        use_tls=cfg["tls"],
        use_ssl=cfg["ssl"],
        timeout=10,
    )
    mail = EmailMultiAlternatives(
        "[VIGILANT SPHERE] Alert digest",
        "Open the local application for recorded evidence.",
        cfg["sender"],
        cfg["recipients"],
        connection=connection,
    )
    mail.attach_alternative(body, "text/html")
    if mail.send(fail_silently=False) == 0:
        raise RuntimeError("Digest not delivered")
    config.last_digest_sent_at = boundary if len(alerts) >= 1000 else now
    config.save(update_fields=["last_digest_sent_at"])
    return f"Digest sent: {len(alerts)} alerts"
