#!/usr/bin/env python3
"""
parse_report.py — Shadow CFI Report Parser
Reads cfi_report.json and prints a coloured terminal summary.
Usage: python3 parse_report.py [path/to/cfi_report.json]
"""

import json
import sys
import os

# ── ANSI colour codes ──────────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"
GREY    = "\033[90m"

BG_RED    = "\033[41m"
BG_YELLOW = "\033[43m"

# ── Helpers ───────────────────────────────────────────────────────────────────

def severity_colour(sev):
    if sev == "CRITICAL":
        return f"{BOLD}{RED}{sev}{RESET}"
    elif sev == "HIGH":
        return f"{BOLD}{YELLOW}{sev}{RESET}"
    return f"{WHITE}{sev}{RESET}"

def type_label(vtype):
    labels = {
        "shadow_stack":       f"{MAGENTA}Shadow Stack Overwrite{RESET}",
        "cfi_indirect":       f"{CYAN}Indirect Call Hijack{RESET}",
        "cfi_invalid_target": f"{RED}Invalid Call Target{RESET}",
    }
    return labels.get(vtype, f"{WHITE}{vtype}{RESET}")

def divider(char="─", width=70, colour=GREY):
    print(f"{colour}{char * width}{RESET}")

def section(title):
    divider("═")
    print(f"{BOLD}{WHITE}  {title}{RESET}")
    divider("═")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "cfi_report.json"

    if not os.path.exists(path):
        print(f"{RED}[!] File not found: {path}{RESET}")
        print(f"{DIM}    Run the Pin tool first to generate cfi_report.json{RESET}")
        sys.exit(1)

    with open(path) as f:
        report = json.load(f)

    summary    = report.get("summary", {})
    violations = report.get("violations", [])

    total      = summary.get("total_violations", 0)
    ss_count   = summary.get("shadow_stack_violations", 0)
    cfi_count  = summary.get("cfi_violations", 0)
    targets    = summary.get("cfi_observed_targets", 0)
    exit_code  = summary.get("exit_code", "?")

    print()
    section("SHADOW CFI — ANALYSIS REPORT")
    print()

    # ── Summary cards ─────────────────────────────────────────────────────────
    status_colour = RED if total > 0 else GREEN
    status_label  = "VULNERABLE" if total > 0 else "CLEAN"

    print(f"  Status          : {BOLD}{status_colour}{status_label}{RESET}")
    print(f"  Total Violations: {BOLD}{RED if total > 0 else GREEN}{total}{RESET}")
    print(f"  Shadow Stack    : {BOLD}{RED if ss_count > 0 else GREEN}{ss_count}{RESET}")
    print(f"  CFI Violations  : {BOLD}{RED if cfi_count > 0 else GREEN}{cfi_count}{RESET}")
    print(f"  Profile Targets : {CYAN}{targets}{RESET}")
    print(f"  Exit Code       : {GREY}{exit_code}{RESET}")
    print()

    if not violations:
        divider()
        print(f"  {GREEN}{BOLD}✔ No violations detected.{RESET}")
        divider()
        print()
        return

    # ── Violation breakdown table ──────────────────────────────────────────────
    section(f"VIOLATIONS  ({total} found)")
    print()

    # Count by type
    type_counts = {}
    for v in violations:
        t = v.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    print(f"  {BOLD}Breakdown by type:{RESET}")
    for t, count in type_counts.items():
        print(f"    {type_label(t):45s}  ×{count}")
    print()
    divider()

    # ── Per-violation detail ───────────────────────────────────────────────────
    for v in violations:
        vid      = v.get("id", "?")
        vtype    = v.get("type", "unknown")
        severity = v.get("severity", "?")
        tid      = v.get("thread_id", "?")
        symbol   = v.get("symbol", "(unknown)")
        attack   = v.get("attack_description", "")
        fix      = v.get("fix_suggestion", "")

        print()
        print(f"  {BOLD}Violation #{vid}{RESET}  {severity_colour(severity)}  {type_label(vtype)}")
        print()

        # Addresses
        if vtype == "shadow_stack":
            expected = v.get("expected_return", "?")
            actual   = v.get("actual_return", "?")
            print(f"    {DIM}Thread      :{RESET}  {tid}")
            print(f"    {DIM}Expected RET:{RESET}  {GREEN}{expected}{RESET}")
            print(f"    {DIM}Actual RET  :{RESET}  {RED}{actual}{RESET}  ← overwritten")
            print(f"    {DIM}Symbol      :{RESET}  {YELLOW}{symbol}{RESET}")
        else:
            target   = v.get("target", "?")
            callsite = v.get("callsite", "?")
            print(f"    {DIM}Thread      :{RESET}  {tid}")
            print(f"    {DIM}Callsite    :{RESET}  {CYAN}{callsite}{RESET}")
            print(f"    {DIM}Target      :{RESET}  {RED}{target}{RESET}  ← hijacked")
            print(f"    {DIM}Symbol      :{RESET}  {YELLOW}{symbol}{RESET}")

        print()

        # Attack description
        print(f"    {BOLD}{MAGENTA}⚠  Attack:{RESET}")
        # Word-wrap at 65 chars
        words = attack.split()
        line  = "       "
        for word in words:
            if len(line) + len(word) + 1 > 72:
                print(line)
                line = "       " + word
            else:
                line += (" " if line.strip() else "") + word
        if line.strip():
            print(line)

        print()

        # Fix suggestion
        print(f"    {BOLD}{GREEN}✔  Fix:{RESET}")
        # Split on '. ' to show as bullet points
        sentences = [s.strip() for s in fix.replace(". ", ".|").split("|") if s.strip()]
        for sentence in sentences:
            if not sentence.endswith("."):
                sentence += "."
            print(f"       • {sentence}")

        print()
        divider()

    print()
    print(f"  {DIM}Report: {path}{RESET}")
    print()

if __name__ == "__main__":
    main()
