# skill-audit

Offline security auditor for agent skill instruction files (MD format).

Detects 7 risk categories in agent skill definitions before they reach your orchestrator:
eval/exec injection, shell escape, dynamic imports, unauthorized file writes, network calls, hardcoded credentials, command injection.

**Zero dependencies.** Python 3.8+, no pip install, no network.

## Why

Agent skills are untrusted instructions executed by LLM orchestrators. Malicious skills can inject system commands, exfiltrate files, or poison downstream agents. skill-audit scans skill files BEFORE they touch your orchestrator.

## Usage

```bash
python skill_audit.py path/to/skill.md
python skill_audit.py path/to/skill.md --json
```

## Example

```
skill-audit v1.1.0
File: /skills/evil-skill.md
Lines: 42 | Chars: 1890
Verdict: RISK FOUND

--- Findings ---
  [CRITICAL] L15: Code execution via eval()/exec() in skill instruction
         -> result = eval(user_input)
         Fix: Remove dynamic code execution; use declarative instructions
  [HIGH] L28: Dynamic module import in skill instruction
         -> mod = importlib.import_module(user_pkg)
         Fix: Use static imports only
```

## Risk categories

| Risk | Severity | What it catches |
|------|----------|-----------------|
| eval_injection | CRITICAL | eval(), exec() calls |
| subprocess_escape | CRITICAL | subprocess, os.system, os.popen |
| credential_leak | CRITICAL | Hardcoded keys, tokens, passwords |
| command_injection | CRITICAL | Shell injection via user input |
| dynamic_import | HIGH | importlib, __import__ |
| file_write | MEDIUM | File write operations |
| network_call | MEDIUM | HTTP requests in skills |

## Exit codes

- 0: CLEAN — no risks detected
- 1: RISK FOUND — review findings
- 2: Error (file not found, etc.)

## License

MIT