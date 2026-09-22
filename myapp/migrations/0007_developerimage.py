# Generated manually for the DeveloperImage model.
from django.db import migrations, models
import django.core.validators


class Migration(migrations.Migration):
    dependencies = [("myapp", "0006_applicationrelease_cmsannouncement_cmsblock_and_more")]
    operations = [migrations.CreateModel(name="DeveloperImage", fields=[
        ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
        ("image", models.ImageField(upload_to="developer/", validators=[django.core.validators.FileExtensionValidator(["jpg", "jpeg", "png", "webp"])])),
        ("title", models.CharField(blank=True, max_length=180)),
        ("alt_text", models.CharField(default="Vigilant Sphere developer", max_length=220)),
        ("is_active", models.BooleanField(default=True)),
        ("display_order", models.PositiveIntegerField(default=0)),
        ("uploaded_at", models.DateTimeField(auto_now_add=True)), ("updated_at", models.DateTimeField(auto_now=True)),
    ], options={"ordering": ["display_order", "id"]}), migrations.RunPython(
        lambda apps, schema_editor: apps.get_model("myapp", "DeveloperImage").objects.get_or_create(
            image="developer/dhithimos-es.jpg",
            defaults={"title": "Dhithimos ES", "alt_text": "Dhithimos ES, Vigilant Sphere developer", "is_active": True, "display_order": 0},
        ),
        migrations.RunPython.noop,
    )]
