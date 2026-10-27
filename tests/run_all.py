#!/usr/bin/env python3
"""Ejecuta todas las suites tests/test_*.py, cada una en su propio proceso (`python3 -I`), y resume.
Falla (código 1) si alguna suite falla o si algún test se OMITE: estos tests no deben depender de ningún programa real.
Uso: python3 -I tests/run_all.py [--min-tests N]
"""
import argparse
import glob
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def run_suite(path):
    p = subprocess.run([sys.executable, "-I", path], capture_output=True, text=True, timeout=600)
    out = p.stdout + p.stderr
    m = re.search(r"Ran (\d+) tests? in", out)
    ran = int(m.group(1)) if m else 0
    sk = re.search(r"skipped=(\d+)", out)
    return {"suite": os.path.basename(path), "rc": p.returncode, "ran": ran, "skipped": int(sk.group(1)) if sk else 0,
            "ok": p.returncode == 0 and bool(re.search(r"^OK", out, re.M)), "out": out}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--min-tests", type=int, default=0, help="falla si el total de tests es menor")
    a = ap.parse_args(argv[1:])
    res = [run_suite(p) for p in sorted(glob.glob(os.path.join(HERE, "test_*.py")))]
    total = sum(r["ran"] for r in res)
    skipped = sum(r["skipped"] for r in res)
    for r in res:
        print("%-24s %3d tests  %s%s" % (r["suite"], r["ran"], "OK" if r["ok"] else "FALLA", ("  (omitidos: %d)" % r["skipped"]) if r["skipped"] else ""))
    print("TOTAL: %d tests, %d omitidos" % (total, skipped))
    bad = [r for r in res if not r["ok"]]
    for r in bad:
        print("\n--- salida de %s ---\n%s" % (r["suite"], r["out"][-2000:]))
    if skipped:
        print("ERROR: hay tests omitidos (no deben depender de nada externo)")
    if total < a.min_tests:
        print("ERROR: %d tests < --min-tests %d" % (total, a.min_tests))
    return 1 if (bad or skipped or total < a.min_tests) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
