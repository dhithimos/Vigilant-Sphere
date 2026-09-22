import getpass
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from myapp.wifi_audit_service import run_audit


class Command(BaseCommand):
    help = "Run one passive audit attributed to --username; OS account determines visible profiles."

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True)

    def handle(self, *args, **options):
        try:
            user = get_user_model().objects.get(
                username=options["username"], is_active=True
            )
        except get_user_model().DoesNotExist:
            raise CommandError("Active attribution account not found")
        try:
            job, state, _ = run_audit(user)
        except PermissionError as exc:
            raise CommandError(str(exc))
        self.stdout.write(
            f"OS account: {getpass.getuser()}; application account ID: {user.pk}; job: {job.pk}; status: {state}"
        )
        if state in {"COLLECTION ERROR", "PERMISSION DENIED"}:
            raise CommandError("Metadata collection failed")
