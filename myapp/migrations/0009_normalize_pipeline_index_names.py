from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("myapp", "0008_unified_security_pipeline")]

    operations = [
        migrations.RenameIndex(model_name="finding", old_name="myapp_find_severit_956f00_idx", new_name="myapp_findi_severit_828657_idx"),
        migrations.RenameIndex(model_name="finding", old_name="myapp_find_scanner_3f529c_idx", new_name="myapp_findi_scanner_17e989_idx"),
        migrations.RenameIndex(model_name="scanjob", old_name="myapp_scanj_status_0b759e_idx", new_name="myapp_scanj_status_656a9a_idx"),
    ]
