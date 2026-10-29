"""Browser smoke test: every view renders under the real CSP with no console output.

Starts `cti serve` on the built dashboard and an export folder, loads each view in headless
Chrome and fails if a view doesn't render or the browser logs anything: a CSP or Trusted
Types violation, a failed request, or a script error. Chrome logs violations as console
messages, so "no console output" is the check.

    python web/scripts/smoke.py --export-dir web/fixtures [--chrome PATH]
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

# view -> its page heading (the nav labels appear on every page, so they prove nothing)
VIEWS = {
    "overview": "<h1>Which threats deserve",
    "queue": "<h1>Risk queue",
    "threats": "<h1>Threats",
    "landscape": "<h1>Risk landscape",
    "weakness": "<h1>Weakness graph",
    "attack": "<h1>ATT&amp;CK graph",
    "indicators": "<h1>Indicators",
    "evaluation": "<h1>Evaluation",
}
CHROMES = (
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)


def find_chrome(given: str | None) -> str:
    for candidate in [given] if given else CHROMES:
        path = shutil.which(candidate) or (candidate if Path(candidate).exists() else None)
        if path:
            return path
    sys.exit("no Chrome found; pass --chrome")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--export-dir", required=True)
    ap.add_argument("--dist", default="web/dist")
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--chrome")
    ap.add_argument("--cti", default=shutil.which("cti") or "cti")
    args = ap.parse_args()
    chrome = find_chrome(args.chrome)
    server = subprocess.Popen(  # noqa: S603 - fixed argv
        [
            args.cti,
            "serve",
            "--dist",
            args.dist,
            "--export-dir",
            args.export_dir,
            "--port",
            str(args.port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{args.port}/"
    failures = []
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(base, timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        else:
            return print("server did not start") or 1
        if server.poll() is not None:  # something else answered on the port
            return print(f"cti serve exited; is port {args.port} in use?") or 1
        with tempfile.TemporaryDirectory() as profile:
            for view, marker in VIEWS.items():
                run = subprocess.run(  # noqa: S603 - fixed argv
                    [
                        chrome,
                        "--headless=new",
                        "--disable-gpu",
                        "--no-first-run",
                        f"--user-data-dir={profile}",
                        "--enable-logging=stderr",
                        "--v=0",
                        "--virtual-time-budget=5000",
                        "--dump-dom",
                        f"{base}#/{view}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=90,
                    check=False,
                )
                console = [line for line in run.stderr.splitlines() if ":CONSOLE" in line]
                active = f'href="#/{view}" aria-current="page"'
                rendered = marker in run.stdout and active in run.stdout
                status = "ok" if rendered and not console else "FAIL"
                print(f"  {status:4} {view}")
                if not rendered:
                    failures.append(f"{view}: did not render ({marker!r} missing)")
                failures += [f"{view}: {line.split('CONSOLE', 1)[1][:300]}" for line in console]
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
    for failure in failures:
        print(f"  {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
