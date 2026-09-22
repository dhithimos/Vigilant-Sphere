from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("myapp", "0002_contactmessage_scanresult_useractivity"),
    ]

    operations = [
        migrations.AddField(
            model_name="customuser",
            name="address",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="customuser",
            name="age",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="customuser",
            name="gender",
            field=models.CharField(blank=True, max_length=40),
        ),
        migrations.AddField(
            model_name="useractivity",
            name="device",
            field=models.CharField(blank=True, max_length=300),
        ),
        migrations.AddField(
            model_name="useractivity",
            name="ip_address",
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="useractivity",
            name="place",
            field=models.CharField(blank=True, default="Local/Unknown", max_length=150),
        ),
        migrations.CreateModel(
            name="ScanFeedback",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("rating", models.PositiveSmallIntegerField(default=5)),
                ("comment", models.TextField(blank=True)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("device", models.CharField(blank=True, max_length=300)),
                ("place", models.CharField(blank=True, default="Local/Unknown", max_length=150)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("scan", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="feedback", to="myapp.scanresult")),
                ("user", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AlterField(
            model_name="scanresult",
            name="score",
            field=models.IntegerField(default=0),
        ),
    ]
