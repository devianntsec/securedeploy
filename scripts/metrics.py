#!/usr/bin/env python3
"""Compara los reportes de Lynis antes/después del hardening y imprime una tabla Markdown.

Uso: python3 scripts/metrics.py   (lee reports/<host>/lynis-report-{before,after}.dat)
"""

import re
import sys
from pathlib import Path


def parse(path: Path) -> dict[str, int]:
    text = path.read_text(errors="ignore")
    idx = re.search(r"^hardening_index=(\d+)", text, re.M)
    return {
        "hardening_index": int(idx.group(1)) if idx else -1,
        "warnings": len(re.findall(r"^warning\[\]=", text, re.M)),
        "suggestions": len(re.findall(r"^suggestion\[\]=", text, re.M)),
    }


def main() -> int:
    base = Path(__file__).resolve().parent.parent / "reports"
    hosts = [d for d in base.iterdir() if d.is_dir()] if base.exists() else []
    found = False
    for host in sorted(hosts):
        before, after = host / "lynis-report-before.dat", host / "lynis-report-after.dat"
        if not (before.exists() and after.exists()):
            continue
        found = True
        b, a = parse(before), parse(after)
        print(f"### {host.name}\n")
        print("| Métrica | Antes | Después | Delta |\n|---|---|---|---|")
        for k in ("hardening_index", "warnings", "suggestions"):
            print(f"| {k} | {b[k]} | {a[k]} | {a[k] - b[k]:+d} |")
    if not found:
        print("No hay pares before/after en reports/.")
        print("Ejecuta: make audit-before, make harden, make audit-after")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
