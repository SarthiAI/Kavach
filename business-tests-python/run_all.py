"""
Run every scenario in this folder, show each one's output, and end
with a summary table. Exit code is 0 if every scenario passed, 1 if
any failed.

Usage:

    python run_all.py              # run every tier
    python run_all.py --tier 1     # run only tier 1
    python run_all.py --only 05    # run scripts whose filename contains 05
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
VENV_PYTHON = HERE / "venv" / "bin" / "python"


def discover(tier, only):
    tier_dirs = sorted(p for p in HERE.glob("tier*") if p.is_dir())
    if tier is not None:
        tier_dirs = [d for d in tier_dirs if d.name == f"tier{tier}"]

    scripts = []
    for td in tier_dirs:
        for f in sorted(td.glob("*.py")):
            if f.name.startswith("_") or f.name.startswith("."):
                continue
            if only and only not in f.name:
                continue
            scripts.append(f)
    return scripts


def main():
    ap = argparse.ArgumentParser(description="Run every Kavach business-tests scenario.")
    ap.add_argument("--tier", type=int, choices=[1, 2, 3], default=None,
                    help="run only scripts in tier<N>/.")
    ap.add_argument("--only", type=str, default=None,
                    help="filter by substring match on filename.")
    args = ap.parse_args()

    if not VENV_PYTHON.exists():
        print(f"[ERROR] venv python not found at {VENV_PYTHON}", file=sys.stderr)
        print("        create it first: python -m venv venv && ./venv/bin/pip install kavach-sdk",
              file=sys.stderr)
        return 1

    scripts = discover(args.tier, args.only)
    if not scripts:
        print("No scenarios matched. Nothing to run.")
        return 0

    bar = "=" * 72
    print(bar)
    print(f"Running {len(scripts)} scenario(s) with {VENV_PYTHON}")
    if args.tier is not None:
        print(f"  tier filter   : tier {args.tier}")
    if args.only:
        print(f"  substring filter: {args.only!r}")
    print(bar)

    results = []
    for script in scripts:
        print()
        print(bar)
        print(f"> {script.relative_to(HERE)}")
        print(bar)
        start = time.monotonic()
        result = subprocess.run([str(VENV_PYTHON), str(script)], cwd=str(HERE))
        elapsed = time.monotonic() - start
        results.append((script, result.returncode == 0, elapsed))

    print()
    print(bar)
    print("Summary")
    print(bar)
    for script, ok, elapsed in results:
        mark = "PASS" if ok else "FAIL"
        rel = str(script.relative_to(HERE))
        print(f"  [{mark}] {rel:<54} {elapsed:>6.2f}s")
    print(bar)

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    total_time = sum(e for _, _, e in results)
    if passed == total:
        print(f"{passed}/{total} scenarios passed in {total_time:.2f}s")
    else:
        failing = total - passed
        print(f"{passed}/{total} scenarios passed, {failing} FAILED, total {total_time:.2f}s")
    print(bar)

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
