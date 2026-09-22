from django.core.management.base import BaseCommand, CommandError
from myapp.alerts import send_digest


class Command(BaseCommand):
    help = "Send an additive digest using environment-only SMTP authentication."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--force", action="store_true")

    def handle(self, *args, **options):
        try:
            self.stdout.write(
                send_digest(dry_run=options["dry_run"], force=options["force"])
            )
        except Exception as exc:
            raise CommandError(type(exc).__name__ + ": digest delivery failed")
