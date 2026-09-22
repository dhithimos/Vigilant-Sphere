from datetime import timedelta
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db.models import Q, Count
from django.utils import timezone
from myapp.models import IndicatorOfCompromise


class Command(BaseCommand):
    help = "Deactivate stale indicators; never delete. local_reviewed is included unless excluded."

    def add_arguments(self, p):
        p.add_argument("--dry-run", action="store_true")
        p.add_argument("--exclude-source", action="append", default=[])

    def handle(self, *args, **options):
        cutoff = timezone.now() - timedelta(days=settings.IOC_EXPIRY_DAYS)
        rows = (
            IndicatorOfCompromise.objects.filter(is_active=True)
            .filter(
                Q(last_seen__lt=cutoff)
                | Q(last_seen__isnull=True, discovered_at__lt=cutoff)
            )
            .exclude(source__in=options["exclude_source"])
        )
        counts = list(rows.values("source").annotate(count=Count("pk")))
        for row in counts:
            self.stdout.write(f"{row['source']}: {row['count']}")
        total = sum(x["count"] for x in counts)
        if not options["dry_run"]:
            rows.update(is_active=False)
        self.stdout.write(
            f"{'Would deactivate' if options['dry_run'] else 'Deactivated'} {total}; deleted 0"
        )
