from django.core.management.base import BaseCommand
from myapp.analysis.ioc_correlation import reviewed_entries, upsert_indicator


class Command(BaseCommand):
    help = "Sync reviewed local entries; retired rows stay retired unless --reactivate is supplied."

    def add_arguments(self, parser):
        parser.add_argument("--reactivate", action="store_true")
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        rows = list(reviewed_entries())
        if not options["dry_run"]:
            for row in rows:
                upsert_indicator(row, options["reactivate"])
        self.stdout.write(
            f"{'Would sync' if options['dry_run'] else 'Synced'} {len(rows)} reviewed indicators"
        )
