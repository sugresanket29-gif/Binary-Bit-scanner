# MCP Server Scan Report

- **Target:** `servers\command_server\server.py`
- **Generated:** 2026-10-16 05:10 UTC
- **Modules:** static
- **Result:** FAIL (fail-on: high)

## Summary

| Severity | Count |
| --- | ---: |
| HIGH | 1 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 0 |

## Findings

| ID | Severity | Location | Title |
| --- | --- | --- | --- |
| CMD-002 | HIGH | `servers\command_server\server.py:27` | os.system / os.popen call |

## Details

### CMD-002: os.system / os.popen call

- **ID:** CMD-002
- **Severity:** HIGH
- **Category:** static
- **Location:** `servers\command_server\server.py:27`
- **Evidence:** `return os.popen("echo " + command).read()`
- **Fix:** Use subprocess.run([...]) with an argument list.
