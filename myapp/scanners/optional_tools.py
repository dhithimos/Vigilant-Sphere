"""Optional local engines; invoke only installed tools, never execute the sample."""

import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path
from django.conf import settings
from .target import module_result


def analyze(data, name):
    results = []
    if importlib.util.find_spec("yara"):
        import yara

        rules = sorted(settings.YARA_RULES_DIR.glob("*.yar"))[:50]
        if rules:
            try:
                compiled = yara.compile(
                    filepaths={str(i): str(p) for i, p in enumerate(rules)}
                )
                matches = compiled.match(data=data, timeout=5)
                results.append(
                    module_result(
                        "yara",
                        name,
                        "file",
                        data={
                            "status": "Observed",
                            "matched_rules": [x.rule for x in matches],
                            "note": "Rule matches require analyst interpretation; no safety verdict.",
                        },
                    )
                )
            except Exception:
                results.append(
                    module_result(
                        "yara",
                        name,
                        "file",
                        "error",
                        errors=["YARA compilation or matching failed."],
                    )
                )
        else:
            results.append(
                module_result(
                    "yara",
                    name,
                    "file",
                    "not_configured",
                    data={
                        "status": "Not Configured",
                        "detail": "Install reviewed .yar rules in yara_rules.",
                    },
                )
            )
    else:
        results.append(
            module_result(
                "yara", name, "file", "unsupported", data={"status": "Not Installed"}
            )
        )
    executable = shutil.which("clamscan")
    if not executable:
        results.append(
            module_result(
                "clamav", name, "file", "unsupported", data={"status": "Not Installed"}
            )
        )
    else:
        try:
            with tempfile.TemporaryDirectory(prefix="vigilant-") as folder:
                sample = Path(folder) / "sample.bin"
                sample.write_bytes(data)
                run = subprocess.run(
                    [executable, "--no-summary", "--stdout", str(sample)],
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if run.returncode in {0, 1}:
                    results.append(
                        module_result(
                            "clamav",
                            name,
                            "file",
                            data={
                                "status": "Observed",
                                "detection_observed": run.returncode == 1,
                                "engine_output": run.stdout.replace(
                                    str(sample), "sample"
                                )[:2000],
                                "limitation": "Local signature database only; a non-match is not a safety guarantee.",
                            },
                        )
                    )
                else:
                    results.append(
                        module_result(
                            "clamav",
                            name,
                            "file",
                            "error",
                            errors=["Engine unavailable or signatures missing."],
                        )
                    )
        except (OSError, subprocess.TimeoutExpired):
            results.append(
                module_result(
                    "clamav",
                    name,
                    "file",
                    "unavailable",
                    errors=["ClamAV timeout or unavailable."],
                )
            )
    return results
