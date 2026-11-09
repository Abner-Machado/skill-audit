#!/usr/bin/env python3
"""
skill-audit — Offline security auditor for AI agent skill files.
Detects risky patterns in skill markdown: eval, exec, dynamic imports,
subprocess calls, and other agent-unsafe instructions.
Zero dependencies. Pure Python 3.8+.

Usage: python skill_audit.py <path/to/skill.md>
"""

import sys
import re
import json
from pathlib import Path

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


def audit_file(filepath: str) -> dict:
    path = Path(filepath)
    if not path.exists():
        return {"error": f"File not found: {filepath}"}
    if not path.is_file():
        return {"error": f"Not a file: {filepath}"}

    content = path.read_text(encoding="utf-8", errors="replace")
    lines = content.split("\n")
    findings = []
    stats = {"total_lines": len(lines), "total_chars": len(content)}

    for risk_id, risk in RISK_PATTERNS.items():
        for pattern in risk["patterns"]:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "risk_id": risk_id,
                        "severity": risk["severity"],
                        "message": risk["message"],
                        "line": i,
                        "snippet": line.strip()[:120],
                        "remediation": risk["remediation"]
                    })

    findings.sort(key=lambda f: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[f["severity"]],
        f["line"]
    ))

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


def main():
    if len(sys.argv) < 2:
        print("Usage: python skill_audit.py <path/to/skill.md> [--json]")
        sys.exit(1)

    as_json = "--json" in sys.argv
    filepath = sys.argv[1]

    result = audit_file(filepath)

    if "error" in result:
        print(result["error"], file=sys.stderr)
        sys.exit(2)

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"skill-audit v1.0.0")
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

    sys.exit(0 if result.get("passed", False) else 1)


if __name__ == "__main__":
    main()