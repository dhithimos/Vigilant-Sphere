"""Optional worker entry point.

If Celery is installed and configured, call this function from a Celery task.
The core project intentionally does not require Redis/Celery for local use.
"""

from .security_pipeline import execute_job


def run_scan_job(job_id: int) -> None:
    execute_job(job_id)
