import csv, json, sys
from django.core.management.base import BaseCommand
from myapp.models import IndicatorOfCompromise


class Command(BaseCommand):
    help = "Export active indicators. Prefer JSON for exchange; untrusted CSV values are unsafe in spreadsheets."

    def add_arguments(self, p):
        p.add_argument("path")
        p.add_argument("--format", choices=["json", "csv"], default="json")

    def handle(self, *args, **options):
        keys = ["ioc_type", "value", "source", "threat_name", "confidence"]
        rows = (
            IndicatorOfCompromise.objects.filter(is_active=True)
            .values(*keys)
            .order_by("pk")
        )
        with open(options["path"], "w", encoding="utf-8", newline="") as stream:
            if options["format"] == "json":
                json.dump(list(rows), stream, indent=2)
            else:
                writer = csv.DictWriter(stream, fieldnames=keys)
                writer.writeheader()
                for row in rows.iterator():
                    writer.writerow(row)
        self.stdout.write("Active indicators exported; review before importing")
