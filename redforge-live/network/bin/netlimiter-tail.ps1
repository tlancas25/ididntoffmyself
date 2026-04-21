# Stub -- Phase 2 work.
#
# Will tail NetLimiter's per-connection log (default location:
# C:\ProgramData\Locktime Software\NetLimiter\log\) and emit anomalies
# into triage-queue.jsonl the same shape watcher.ps1 writes.
#
# Needs confirmation of NetLimiter's log format on the operator's
# install (v4 vs v5). See ../docs/netlimiter-integration.md (in
# sibling watchdog/ scope) for format reconnaissance notes.
#
# Not wired up in v0.1. Safe to ignore until Phase 2.

Write-Warning "netlimiter-tail.ps1 is a Phase 2 stub. Not implemented yet."
exit 0
