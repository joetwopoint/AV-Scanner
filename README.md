# TwoPoint_AVScanner

A lightweight **heuristic** “antivirus-style” scanner for FiveM resources.

This is **defensive tooling** meant to help you *review* resources and catch obvious red flags
like dynamic code execution, suspicious HTTP fetch-and-run behavior, and key/secret access.

> It is **NOT** a real antivirus engine and cannot guarantee malware detection.

---

## Install

1. Drop the folder into your server resources, e.g.:
   - `resources/[tools]/TwoPoint_AVScanner`

2. Add to server.cfg:
   - `ensure TwoPoint_AVScanner`

3. (Recommended) Give admins permission:
   - `add_ace group.admin avscanner.scan allow`

---

## Commands

- `/avscan`
  - Scans *all* resources (excluding ones in `Config.ExcludeResources`).
- `/avscanres <resourceName>`
  - Scans a single resource.

A JSON report will be saved to:
- `TwoPoint_AVScanner/reports/avscan_YYYYMMDD_HHMMSS.json` (inside this resource folder)

---

## Notes / Limitations

- FiveM doesn’t provide a perfect “list all files in a resource” API.
  This scanner reads:
  - `fxmanifest.lua` / `__resource.lua` and scans quoted file paths it discovers,
  - plus a set of common entry files (server.lua, client.lua, config.lua, html/index.html, etc.)

- Results are **heuristics** and can be noisy:
  - e.g., Discord webhooks may be normal logging.
  - Anything flagged should be reviewed manually.

- For real host protection, still run OS-level tools too (e.g., ClamAV on Linux, Defender on Windows).

---

## Tuning

Edit `config.lua`:
- `MinSeverity` to hide low-noise findings
- `SuppressFindings` to hide specific rule IDs/descriptions
- `ExcludeResources` to skip known-good frameworks/tools
- `DiscordWebhook` to get scan summaries posted to Discord

---

## Rule Types (examples)

- **critical**
  - loadstring/load/exec patterns
  - OS command execution (os.execute, io.popen)

- **high**
  - suspicious HTTP sources / fetch-and-run patterns
  - reading secrets like sv_licenseKey via convars

- **medium / low**
  - Discord webhooks
  - resource start/stop behavior
  - possible obfuscation hints

---

## Support

This is built to be small, safe, and easy to extend:
- Add/adjust patterns in `server/server.lua` under `RULES`.
