# NetLimiter integration notes

The operator has **NetLimiter** installed (and installed BEFORE the Trial #1 compromise). NetLimiter showed the attacker's connections but did not alert — this is the canonical example of a monitoring tool whose data wasn't being reviewed semantically. redforge-live's job is to be that semantic reviewer.

## What NetLimiter produces (default install)

- **Per-connection data in the GUI:** process name, PID, remote IP + port, direction, byte count, rule matched. Visible in the "Connections" tab.
- **Log files:** NetLimiter writes logs to:
  - `C:\ProgramData\Locktime Software\NetLimiter\log\` — main per-connection logs (when logging is enabled at the connection level)
  - `C:\ProgramData\Locktime Software\NetLimiter\stats\` — rolling traffic-statistics database (SQLite or proprietary)
- **Default logging level is OFF for per-connection detail.** The user typically has to enable "Log connections" per rule or globally.

**Step 1 of integration is to confirm the operator has per-connection logging enabled.** If not, enable it for the `* > *` default rule in NetLimiter so every connection is recorded.

## Log format reconnaissance (needs verification on operator's install)

Per the Locktime vendor documentation (as of v4.x/5.x):

- Log files rotate daily, named `connections-YYYY-MM-DD.log`
- Format varies by version: older versions emit tab-delimited plaintext; newer versions emit a binary format that requires NetLimiter's own viewer OR the `nlctl.exe` export command.

For integration, preferred path is:
1. Invoke `nlctl.exe export --format csv --from <lastcheck> --to now --output <path>` on each watchdog cycle (if nlctl is available on the install)
2. Parse the CSV
3. Cross-reference destinations against the allowlist in `state/baseline.json.outbound_allowlist`

If nlctl isn't available or the log format is binary, fallback path:

1. Use `Get-NetTCPConnection -State Established` directly (already in `watch.ps1`'s snapshot)
2. Enrich with process signature via `Get-AuthenticodeSignature` on the owning process binary
3. This loses some historical connections NetLimiter would have caught, but captures the current-state picture

## Known tests

- **edgeserv.ru / 95.214.234.238:** NetLimiter will NOT show this during normal operations unless the firewall rule allows it AND the ScreenConnect-class client makes the connection. In Trial #1 the operator blocked these IPs post-discovery. If they reappear, that's auto-malicious (see `prompts/triage.md` IoC list).
- **130.12.180.159 + 64.74.162.109:** same.
- **New previously-unseen IPs with long-lived connections (>5 min):** suspicious. Triage.
- **New destinations on high ephemeral ports (>32000) from signed MS binaries:** suspicious (this is how the RegAsm LOLBin C2 channel in Trial #1 manifested — signed RegAsm.exe making an outbound connection to 130.12.180.159:56009).

## Allowlist population strategy

Initial allowlist (seeded from the operator's known-good software):
- `*.microsoft.com`, `*.microsoftonline.com`, `*.office.com`, `*.outlook.com`, `*.live.com`
- `*.github.com`, `*.githubusercontent.com`, `api.github.com`
- `*.anthropic.com`, `api.anthropic.com`, `claude.ai`
- `*.google.com`, `*.googleapis.com`, `*.gstatic.com`
- `*.cloudflare.com`, `1.1.1.1`, `1.0.0.1`
- `*.amazonaws.com` (for any AWS-hosted tool the operator uses)
- `*.docker.com`, `*.dockerhub.io`
- `*.openai.com` (if OpenAI is in use)
- `*.npmjs.com`, `*.pypi.org`
- Local LAN: `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`
- Tailscale CGNAT: `100.64.0.0/10`

Expand the allowlist over time: when Claude classifies an outbound destination as benign during triage, it adds the destination to `outbound_allowlist` in the baseline.

## What to do when an outbound-destination alert fires

If the watchdog sees a new outbound destination not in the allowlist:

1. Snapshot `ProcessName + RemoteAddress + RemotePort` at the moment of detection.
2. Resolve `RemoteAddress` to a hostname via reverse DNS (may fail; C2 often has no PTR).
3. Query process signer: `Get-AuthenticodeSignature $processBinaryPath`.
4. Classify:
   - Signed by known good publisher (Microsoft, Google, Anthropic, operator-known vendor) + sane-looking destination → benign (add to allowlist).
   - Signed by unknown publisher OR unsigned + uncommon destination → suspicious.
   - Destination in known-bad list OR signed binary with historically-impossible outbound (e.g., RegAsm.exe, MSBuild.exe, InstallUtil.exe) → malicious.

The last bullet — **"signed Microsoft binary making an outbound connection it has no business making"** — is exactly the RegAsm LOLBin pattern from Trial #1. Catching this in real time is the single biggest win this tool offers over Defender alone.

## Open questions

- Does NetLimiter expose an API for programmatic query? (Vendor docs say yes — `nlctl.exe` or a REST-ish interface on a configurable localhost port). Worth confirming on the operator's install.
- Does the operator want redforge-live to create NetLimiter rules (e.g., auto-block on malicious-classification) or just monitor? Current design says monitor-only; auto-rule-creation would require an additional explicit opt-in.
- Should we ingest NetLimiter's per-process historical traffic graphs? Could give Claude richer context ("this process suddenly tripled its bandwidth in the last 15 min"), but adds complexity. Defer to Phase 2.
