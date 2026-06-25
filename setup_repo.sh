#!/bin/bash
# setup_repo.sh — organise shadow_cfi into clean GitHub folder structure
# Run from inside ~/Downloads/shadow_cfi/

set -e
cd "$(dirname "$0")"

echo "[1/5] Creating folder structure..."
mkdir -p pintool vulns web scripts docs obj-intel64

echo "[2/5] Moving Pin tool files..."
cp MyPinTool.cpp pintool/ 2>/dev/null && echo "  ✔ MyPinTool.cpp"
cp makefile pintool/ 2>/dev/null && echo "  ✔ makefile"
cp makefile.rules pintool/ 2>/dev/null && echo "  ✔ makefile.rules"

echo "[3/5] Moving vulnerable source files..."
for f in vuln1.c vuln2.c vuln3.c vuln4.c \
          vuln_ret_overwrite.c vuln_uaf.c \
          vuln_heapspray.c vuln_thread.c \
          cfi_demo.c shadow_demo.c; do
  [ -f "$f" ] && cp "$f" vulns/ && echo "  ✔ $f"
done

echo "[4/5] Moving web and scripts..."
cp dashboard.html web/ 2>/dev/null && echo "  ✔ dashboard.html"
cp server.py web/ 2>/dev/null && echo "  ✔ server.py"
cp parse_report.py scripts/ 2>/dev/null && echo "  ✔ parse_report.py"

echo "[5/5] Done. Final structure:"
find . -not -path './.git/*' -not -path './obj-intel64/*' \
       -not -name '*.o' -not -name '*.so' \
       | sort | sed 's|[^/]*/|  |g'

echo ""
echo "Next steps:"
echo "  git init"
echo "  git add ."
echo "  git commit -m 'Initial commit — CFI-Shield'"
echo "  git remote add origin https://github.com/hemachandran-1206/cfi-shield.git"
echo "  git push -u origin main"
