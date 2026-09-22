from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("myapp", "0007_developerimage")]

    operations = [
        migrations.CreateModel(name="ScanJob", fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("scan_id", models.CharField(max_length=36, unique=True)), ("scan_type", models.CharField(default="combined", max_length=80)),
            ("selected_scanners", models.JSONField(default=list)), ("status", models.CharField(db_index=True, default="QUEUED", max_length=16)),
            ("progress", models.PositiveSmallIntegerField(default=0)), ("scanner_count", models.PositiveSmallIntegerField(default=0)),
            ("completed_scanner_count", models.PositiveSmallIntegerField(default=0)), ("failed_scanner_count", models.PositiveSmallIntegerField(default=0)),
            ("finding_count", models.PositiveIntegerField(default=0)), ("risk_score", models.PositiveSmallIntegerField(default=0)),
            ("error", models.TextField(blank=True)), ("started_at", models.DateTimeField(blank=True, null=True)),
            ("completed_at", models.DateTimeField(blank=True, null=True)), ("created_at", models.DateTimeField(auto_now_add=True)),
            ("asset", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="scan_jobs", to="myapp.assetinventory")),
            ("requested_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="security_scan_jobs", to=settings.AUTH_USER_MODEL)),
        ]),
        migrations.AddIndex(model_name="scanjob", index=models.Index(fields=["status", "created_at"], name="myapp_scanj_status_0b759e_idx")),
        migrations.CreateModel(name="Finding", fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("finding_id", models.CharField(max_length=64, unique=True)), ("fingerprint", models.CharField(db_index=True, max_length=64)),
            ("scanner", models.CharField(db_index=True, max_length=80)), ("finding_type", models.CharField(max_length=100)),
            ("title", models.CharField(max_length=500)), ("description", models.TextField()), ("severity", models.CharField(db_index=True, max_length=10)),
            ("confidence", models.FloatField(default=0.0)), ("risk_score", models.PositiveSmallIntegerField(default=0)),
            ("status", models.CharField(db_index=True, default="OPEN", max_length=20)), ("evidence", models.JSONField(default=dict)),
            ("observations", models.JSONField(default=list)), ("recommendation", models.TextField(blank=True)), ("remediation", models.TextField(blank=True)),
            ("mitre_technique", models.CharField(blank=True, max_length=32)), ("mitre_tactic", models.CharField(blank=True, max_length=100)),
            ("ioc", models.JSONField(default=dict)), ("requires_approval", models.BooleanField(default=True)), ("timestamp", models.DateTimeField(auto_now_add=True, db_index=True)),
            ("asset", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="findings", to="myapp.assetinventory")),
            ("job", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="findings", to="myapp.scanjob")),
        ]),
        migrations.AddIndex(model_name="finding", index=models.Index(fields=["severity", "status", "timestamp"], name="myapp_find_severit_956f00_idx")),
        migrations.AddIndex(model_name="finding", index=models.Index(fields=["scanner", "timestamp"], name="myapp_find_scanner_3f529c_idx")),
        migrations.CreateModel(name="SecurityAlert", fields=[("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")), ("status", models.CharField(db_index=True, default="OPEN", max_length=20)), ("created_at", models.DateTimeField(auto_now_add=True)), ("finding", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="alert", to="myapp.finding"))]),
        migrations.CreateModel(name="FindingEvidence", fields=[("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")), ("source", models.CharField(max_length=120)), ("content", models.JSONField(default=dict)), ("content_hash", models.CharField(db_index=True, max_length=64)), ("created_at", models.DateTimeField(auto_now_add=True)), ("finding", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="evidence_records", to="myapp.finding"))]),
        migrations.CreateModel(name="ResponseApproval", fields=[("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")), ("action", models.CharField(max_length=80)), ("dry_run", models.BooleanField(default=True)), ("status", models.CharField(default="PENDING", max_length=20)), ("result", models.TextField(blank=True)), ("created_at", models.DateTimeField(auto_now_add=True)), ("approved_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="response_approvals", to=settings.AUTH_USER_MODEL)), ("finding", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="approvals", to="myapp.finding")), ("requested_by", models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="response_requests", to=settings.AUTH_USER_MODEL))]),
    ]
