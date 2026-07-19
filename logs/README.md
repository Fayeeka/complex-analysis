# Scenario: Azure/Entra Session Hijacking via Browser Cookie Theft

Synthetic sample data for a **pass-the-cookie** attack: an attacker with code
execution on a victim's workstation steals the browser session cookies for
`login.microsoftonline.com` (Entra ID's SSO cookies, e.g. `ESTSAUTH` /
`ESTSAUTHPERSISTENT`) via the Chrome DevTools Protocol (CDP), exfiltrates
them, then replays them from their own machine to access Microsoft 365 as
the victim — without ever needing the victim's password or an MFA prompt.

This data is entirely fictional, generated for detection-engineering /
correlation-exercise purposes. IP addresses use the RFC 5737 documentation
ranges (`198.51.100.0/24`, `203.0.113.0/24`) rather than real infrastructure.

## Cast

| Field | Value |
|---|---|
| User (display) | Sarah Chen |
| User (on-prem / Sysmon) | `CONTOSO\schen` |
| User (cloud / UPN) | `sarah.chen@contoso.com` |
| Workstation | `CORP-FIN-WK17` (`10.20.4.117`) |
| Normal sign-in IP | `198.51.100.23` (Chicago, US) |
| Attacker IP | `203.0.113.77` (Bucharest, RO) |

## Files

- `windows/sysmon_cookie_theft.json` — Sysmon-style endpoint telemetry (JSON) for the cookie-theft chain on `CORP-FIN-WK17`.
- `cloud/azuread_signin_logs.json` — Entra ID (Azure AD) sign-in log entries for `sarah.chen@contoso.com`, in Microsoft Graph sign-in log schema.

## Timeline

| Time (UTC) | Source | Event |
|---|---|---|
| 13:02:11 | Cloud | Baseline sign-in: password + MFA, from the user's known IP/device (Chicago). Normal daily start-of-work sign-in. |
| 13:05:12 | Endpoint | Baseline `msedge.exe` launch by the user (parent `explorer.exe`, no special flags) — normal browsing. |
| 14:29:41 | Endpoint | `msedge.exe` relaunched **with `--remote-debugging-port=9222`**, spawned from a hidden PowerShell process instead of user interaction. |
| 14:29:50 | Endpoint | `python.exe` connects to `127.0.0.1:9222` — the CDP debug port — then is spawned with a command line that directly references the Edge `Cookies` SQLite database. |
| 14:29:51 | Endpoint | `python.exe` copies the locked `Cookies` DB to a temp file (`cookies_bak.db`) so it can be read while the browser still holds a lock on the original. |
| 14:29:52 | Endpoint | `python.exe` writes `session_dump.json` — decrypted cookie values staged for exfiltration. |
| 14:29:55 | Endpoint | `python.exe` sends the staged file to `203.0.113.77:443`. |
| 14:30:12 | Endpoint | `python.exe` exits. |
| **14:47:09** | **Cloud** | **Sign-in for `sarah.chen@contoso.com` from `203.0.113.77` (Bucharest), ~17 minutes after exfiltration.** No password/MFA challenge — Entra accepted an existing session claim instead. |

## What to look for

**Endpoint (`sysmon_cookie_theft.json`)**
- A browser process launched with `--remote-debugging-port`, especially with a non-interactive parent (PowerShell, cmd, a script host) rather than `explorer.exe`.
- Any process connecting to `127.0.0.1:<debug-port>` shortly after such a launch — indicates CDP automation against the live browser session.
- Process command lines or file reads referencing a browser's cookie database path (`...\User Data\Default\Network\Cookies`), or a locked-file copy of it appearing in `%TEMP%`.
- Outbound connections from that same script/process to an external IP shortly after touching the cookie DB — likely exfiltration.

**Cloud (`azuread_signin_logs.json`)**
- `authenticationDetails[].authenticationStepResultDetail` = **"First factor requirement satisfied by claim in the token"** and `authenticationMethod` = `"Previously satisfied"` — the sign-in reused an existing session/token rather than prompting for credentials.
- `authenticationRequirement` dropping from `multiFactorAuthentication` (baseline) to `singleFactorAuthentication` (attack) for the same user.
- `riskEventTypes_v2` containing `"anomalousToken"` and/or `"unfamiliarFeatures"` (Identity Protection's designation for exactly this kind of token/cookie replay).
- `deviceDetail` showing an unmanaged/non-compliant device with a different OS/browser than the user's known device (`isCompliant: false`, `isManaged: false`).
- `location` jumping to a geography inconsistent with the user's normal pattern with no plausible travel time ("impossible travel").
- Note that `conditionalAccessStatus` can still read `"success"` here — replayed session tokens aren't always re-evaluated against device-compliance Conditional Access policies unless Continuous Access Evaluation (CAE) / token protection is enabled. Don't rely on CA status alone to rule this out.

## Correlating the two sources

Pivot on:
1. **Username** — `schen` (endpoint) ↔ `sarah.chen@contoso.com` (cloud) is the same person.
2. **IP address** — `203.0.113.77` appears as the *exfiltration destination* in the endpoint log at `14:29:55Z` and as the *sign-in source* in the cloud log at `14:47:09Z`. The same attacker infrastructure both received the stolen cookies and was used to replay them.
3. **Timing** — the cloud sign-in follows endpoint exfiltration by ~17 minutes, well within a plausible window for an attacker to load a stolen cookie into their own browser and browse to `login.microsoftonline.com`.
