# Generated manually because the project may be deployed without a local Python runtime.
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("myapp", "0009_normalize_pipeline_index_names")]
    operations = [
        migrations.CreateModel(
            name="TargetScan",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("scan_id", models.CharField(max_length=36, unique=True)),
                ("target", models.CharField(max_length=2048)), ("target_type", models.CharField(db_index=True, max_length=20)),
                ("status", models.CharField(db_index=True, default="COMPLETED", max_length=24)),
                ("risk_score", models.PositiveSmallIntegerField(default=0)), ("risk_level", models.CharField(default="UNKNOWN", max_length=16)),
                ("confidence", models.CharField(default="low", max_length=16)), ("results", models.JSONField(default=list)),
                ("provider_results", models.JSONField(default=list)), ("findings", models.JSONField(default=list)),
                ("started_at", models.DateTimeField()), ("completed_at", models.DateTimeField(blank=True, null=True)), ("created_at", models.DateTimeField(auto_now_add=True)),
                ("user", models.ForeignKey(null=True, on_delete=models.deletion.SET_NULL, related_name="target_scans", to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddIndex(model_name="targetscan", index=models.Index(fields=["user", "created_at"], name="myapp_targe_user_id_4e7e46_idx")),
        migrations.AddIndex(model_name="targetscan", index=models.Index(fields=["target_type", "created_at"], name="myapp_targe_target__02af4e_idx")),
    ]
