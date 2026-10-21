"""Run isolated baseline scans before and after an HTTP header remediation."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from check_zap import NOSNIFF_PLUGIN, read_alerts


HOOKS = Path(__file__).with_name("zap_hooks.py")
CONTROL = '''from app import app, init_db
def remove_nosniff(response):
    response.headers.pop("X-Content-Type-Options", None)
    return response
# Flask executes these callbacks in reverse order; strip the header last.
app.after_request_funcs.setdefault(None, []).insert(0, remove_nosniff)
init_db()
app.run(host="0.0.0.0", port=5000, debug=False)
'''
HEALTH = '''import json, urllib.request
with urllib.request.urlopen("http://127.0.0.1:5000/health", timeout=2) as response:
    assert response.status == 200 and json.load(response) == {"status": "ok"}
'''


def docker(*arguments, **kwargs):
    return subprocess.run(["docker", *arguments], check=True, timeout=600, **kwargs)


def run(image, zap_image, report_dir):
    root = Path(report_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    network = f"devsecops-dast-{uuid.uuid4().hex}"
    docker("network", "create", "--internal", network, stdout=subprocess.DEVNULL)
    try:
        for phase in ("before", "final"):
            output = root / phase
            output.mkdir(parents=True, exist_ok=True)
            # Only the dedicated report directory is writable by ZAP's UID.
            output.chmod(0o777)
            for name in ("zap.json", "zap.html", "coverage.json"):
                (output / name).unlink(missing_ok=True)
            shutil.copyfile(HOOKS, output / "zap_hooks.py")
            app_name = f"{network}-{phase}-app"
            scanner_name = f"{network}-{phase}-scanner"
            command = ["run", "-d", "--name", app_name, "--network", network,
                       "--network-alias", "app", image]
            if phase == "before":
                command.extend(["python", "-c", CONTROL])
            try:
                docker(*command, stdout=subprocess.DEVNULL)
                deadline = time.monotonic() + 60
                while True:
                    health = subprocess.run(
                        ["docker", "exec", app_name, "python", "-c", HEALTH],
                        capture_output=True, timeout=5, check=False,
                    )
                    if health.returncode == 0:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"{phase} application did not become healthy")
                    time.sleep(1)
                print(f"{phase}: /health ready; starting ZAP baseline", flush=True)
                with (output / "scan.log").open("w", encoding="utf-8") as log:
                    docker(
                        "run", "--rm", "--name", scanner_name, "--network", network,
                        "--mount", f"type=bind,source={output},target=/zap/wrk",
                        zap_image, "zap-baseline.py", "-t", "http://app:5000/",
                        "-m", "1", "-T", "3", "-I", "-s", "--autooff",
                        "-z", "-silent", "--hook", "/zap/wrk/zap_hooks.py",
                        "-J", "zap.json", "-r", "zap.html",
                        stdout=log, stderr=subprocess.STDOUT,
                    )
                coverage = json.loads((output / "coverage.json").read_text(encoding="utf-8"))
                if len(coverage) != 6:
                    raise RuntimeError("ZAP did not confirm all six seeded requests")
                alerts = read_alerts(output / "zap.json")
                found = any(str(alert["pluginid"]) == NOSNIFF_PLUGIN for alert in alerts)
                if found != (phase == "before"):
                    raise RuntimeError(f"Unexpected nosniff detection result for {phase}")
                print(
                    f"PASS: {phase}: {len(alerts)} alert types; "
                    f"nosniff missing={found}; six requests confirmed", flush=True,
                )
            finally:
                with (output / "app.log").open("w", encoding="utf-8") as log:
                    subprocess.run(["docker", "logs", app_name], stdout=log,
                                   stderr=subprocess.STDOUT, check=False, timeout=15)
                for name in (scanner_name, app_name):
                    subprocess.run(["docker", "rm", "--force", name], check=False,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=30)
    finally:
        docker("network", "rm", network, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--zap-image", required=True, help="Pinned official ZAP image reference")
    parser.add_argument("--report-dir", default="reports/zap")
    options = parser.parse_args()
    run(options.image, options.zap_image, options.report_dir)
