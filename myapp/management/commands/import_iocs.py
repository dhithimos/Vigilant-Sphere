import csv, json
from pathlib import Path
from django.core.management.base import BaseCommand, CommandError
from myapp.analysis.ioc_correlation import normalize_indicator, upsert_indicator


class Command(BaseCommand):
    help = "Import reviewed JSON/CSV. JSON is preferred for exact instance-to-instance exchange."

    def add_arguments(self, p):
        p.add_argument("path")
        p.add_argument("--dry-run", action="store_true")
        p.add_argument("--strict", action="store_true")
        p.add_argument("--reactivate", action="store_true")

    def handle(self, *args, **options):
        path = Path(options["path"])
        try:
            size = path.stat().st_size
        except OSError:
            raise CommandError("Input file unavailable")
        if size > 10 * 1024 * 1024:
            raise CommandError("Maximum file size is 10 MB")
        try:
            with path.open(encoding="utf-8-sig", newline="") as stream:
                rows = (
                    json.load(stream)
                    if path.suffix.lower() == ".json"
                    else list(csv.DictReader(stream))
                )
        except (ValueError, OSError):
            raise CommandError("Invalid input file")
        if not isinstance(rows, list) or len(rows) > 10000:
            raise CommandError("Expected at most 10000 rows")
        valid = []
        errors = []
        from myapp.models import IndicatorOfCompromise

        for index, row in enumerate(rows, 1):
            try:
                if not isinstance(row, dict) or row.get("ioc_type") not in dict(
                    IndicatorOfCompromise.IOC_TYPES
                ):
                    raise ValueError("Invalid indicator type")
                if (
                    not isinstance(row.get("source"), str)
                    or not row["source"].strip()
                    or len(row["source"]) > 200
                ):
                    raise ValueError("Source required, maximum 200 characters")
                confidence = row.get("confidence", 50)
                if path.suffix.lower() == ".csv":
                    confidence = int(confidence)
                if (
                    isinstance(confidence, bool)
                    or not isinstance(confidence, int)
                    or not 0 <= confidence <= 100
                ):
                    raise ValueError("Confidence must be an integer 0–100")
                item = normalize_indicator(row["ioc_type"], row.get("value", ""))
                valid.append(
                    dict(
                        item,
                        source=row["source"].strip(),
                        confidence=confidence,
                        threat_name=str(row.get("threat_name", ""))[:255],
                    )
                )
            except (ValueError, TypeError) as exc:
                errors.append(f"Row {index}: {exc}")
        for error in errors:
            self.stderr.write(error)
        if errors and options["strict"]:
            raise CommandError("Rejected rows; strict import made no changes")
        if not options["dry_run"]:
            for row in valid:
                upsert_indicator(row, options["reactivate"])
        self.stdout.write(
            f"Accepted {len(valid)}; rejected {len(errors)}; dry_run={options['dry_run']}"
        )
