#!/usr/bin/env python3
"""
skill-audit — Offline security auditor for AI agent skill files.
Detects risky patterns in skill markdown: eval, exec, dynamic imports,
subprocess calls, and other agent-unsafe instructions.
Zero dependencies. Pure Python 3.8+.

Usage: python skill_audit.py <path/to/skill.md> [--json]
       python skill_audit.py --version
       python skill_audit.py --help
"""

import sys
import re
import json
from pathlib import Path

VERSION = "1.1.0"

RISK_PATTERNS = {
    "eval_injection": {
        "patterns": [r"eval\s*\(", r"exec\s*\("],
        "severity": "CRITICAL",
        "message": "Code execution via eval()/exec() in skill instruction",
        "remediation": "Remove dynamic code execution; use declarative instructions"
    },
    "subprocess_escape": {
        "patterns": [r"subprocess\.", r"os\.system\s*\(", r"os\.popen\s*\("],
        "severity": "CRITICAL",
        "message": "Shell command execution in skill instruction",
        "remediation": "Never call subprocess or os.system from skill instructions"
    },
    "dynamic_import": {
        "patterns": [r"__import__\s*\(", r"importlib\.import_module"],
        "severity": "HIGH",
        "message": "Dynamic module import in skill instruction",
        "remediation": "Use static imports only"
    },
    "file_write": {
        "patterns": [r"open\s*\(.*['\"][wa]", r"Path\(.*\)\.write"],
        "severity": "MEDIUM",
        "message": "File write operation in skill instruction",
        "remediation": "Restrict file writes to approved directories"
    },
    "network_call": {
        "patterns": [r"requests\.", r"urllib\.", r"http\.client", r"fetch\s*\("],
        "severity": "MEDIUM",
        "message": "Network call in skill instruction",
        "remediation": "Prefer local-only operations"
    },
    "credential_leak": {
        "patterns": [r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{8,}"],
        "severity": "CRITICAL",
        "message": "Potential hardcoded credential in skill instruction",
        "remediation": "Remove credentials; use environment variables"
    },
    "command_injection": {
        "patterns": [r"os\.system\s*\(.*\$", r"subprocess\.run\s*\(.*shell"],
        "severity": "CRITICAL",
        "message": "Command injection risk in skill instruction",
        "remediation": "Never pass user input to shell commands"
    }
}

# Risks that describe the same underlying danger on a single line. When several
# match the same line we keep the most specific one instead of reporting noise.
EXEC_FAMILY = ("command_injection", "eval_injection", "subprocess_escape")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

USAGE = (
    "Usage: python skill_audit.py <path/to/skill.md> [--json]\n"
    "       python skill_audit.py --version\n"
    "       python skill_audit.py --help"
)


def audit_file(filepath: str) -> dict:
    path = Path(filepath)
    if not path.exists():
        return {"error": f"File not found: {filepath}"}
    if not path.is_file():
        return {"error": f"Not a file: {filepath}"}

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"error": f"Cannot read {filepath}: {exc}"}

    lines = content.split("\n")
    stats = {"total_lines": len(lines), "total_chars": len(content)}

    # per_line[line_no][risk_id] = snippet ; keeps one entry per risk per line
    per_line = {}
    for risk_id, risk in RISK_PATTERNS.items():
        for pattern in risk["patterns"]:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    per_line.setdefault(i, {})[risk_id] = line.strip()[:120]

    findings = []
    for line_no in sorted(per_line):
        hits = per_line[line_no]
        exec_hits = [r for r in EXEC_FAMILY if r in hits]
        if len(exec_hits) > 1:
            keep = exec_hits[0]
            others = [r for r in exec_hits[1:]]
            hits = {r: v for r, v in hits.items() if r not in others}
            suffix = ", ".join(RISK_PATTERNS[r]["message"].split(" in ")[0].lower()
                               for r in others)
            hits[keep] = hits[keep] + f" [also: {suffix}]"

        for risk_id, snippet in hits.items():
            risk = RISK_PATTERNS[risk_id]
            findings.append({
                "risk_id": risk_id,
                "severity": risk["severity"],
                "message": risk["message"],
                "line": line_no,
                "snippet": snippet[:120],
                "remediation": risk["remediation"]
            })

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["line"]))

    summary = {
        "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
        "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "LOW": sum(1 for f in findings if f["severity"] == "LOW")
    }

    passed = all(v == 0 for v in summary.values())

    return {
        "file": str(path.absolute()),
        "passed": passed,
        "stats": stats,
        "summary": summary,
        "findings": findings,
        "verdict": "CLEAN" if passed else "RISK FOUND"
    }


def parse_args(argv):
    files = []
    as_json = False
    for arg in argv:
        if arg == "--json":
            as_json = True
        elif arg in ("--version", "--help", "-h"):
            continue
        elif arg.startswith("-"):
            raise ValueError(f"unknown option: {arg}")
        else:
            files.append(arg)
    return files, as_json


def main():
    argv = sys.argv[1:]

    if "--version" in argv:
        print(f"skill-audit v{VERSION}")
        return 0
    if "--help" in argv or "-h" in argv:
        print(USAGE)
        return 0

    try:
        files, as_json = parse_args(argv)
    except ValueError as exc:
        print(f"skill-audit: error: {exc}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2

    if len(files) != 1:
        print(USAGE, file=sys.stderr)
        return 2

    result = audit_file(files[0])

    if "error" in result:
        print(result["error"], file=sys.stderr)
        return 2

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"skill-audit v{VERSION}")
        print(f"File: {result['file']}")
        print(f"Lines: {result['stats']['total_lines']} | Chars: {result['stats']['total_chars']}")
        print(f"Verdict: {result['verdict']}")
        if result['findings']:
            print(f"\n--- Findings ---")
            for f in result['findings']:
                print(f"  [{f['severity']}] L{f['line']}: {f['message']}")
                print(f"         -> {f['snippet']}")
                print(f"         Fix: {f['remediation']}")
        else:
            print("No risks detected.")

    return 0 if result.get("passed", False) else 1


if __name__ == "__main__":
    sys.exit(main())
