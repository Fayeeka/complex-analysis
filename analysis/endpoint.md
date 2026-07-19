# Endpoint Log Analysis — sysmon_cookie_theft.json

**File analyzed:** `logs/windows/sysmon_cookie_theft.json`
**Host:** `CORP-FIN-WK17` (FQDN: `CORP-FIN-WK17.contoso.com`)
**Domain:** `CONTOSO`
**Primary/affected user:** `CONTOSO\schen` (local session, LogonId `0x1e3a300`, TerminalSessionId 2)
**Note:** File is explicitly labeled synthetic/training data, not a real incident — treat findings as a detection-engineering scenario, but the analysis below is written as if investigating it for real.

## Timeline (UTC)

| Time | Event ID | Description |
|---|---|---|
| 2026-07-18 13:05:12.401 | 1 (ProcessCreate) | Baseline: `msedge.exe` launched normally by `schen` — parent `explorer.exe`, no unusual flags. Included for comparison. |
| 2026-07-18 14:29:41.203 | 1 (ProcessCreate) | **msedge.exe relaunched with `--remote-debugging-port=9222 --user-data-dir=...\Temp\edg_prof --headless=new --disable-gpu --no-first-run`**, spawned from a **hidden PowerShell** (`powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process ..."`, PID 7716) rather than user/explorer.exe interaction. This opens the Chrome DevTools Protocol (CDP) on localhost. |
| 2026-07-18 14:29:50.115 | 3 (NetworkConnect) | `python.exe` (PID 8840) connects `127.0.0.1:51422 → 127.0.0.1:9222` — attaching to the CDP debug endpoint just opened. |
| 2026-07-18 14:29:50.560 | 1 (ProcessCreate) | `python.exe` executes `cdp_cookie_grab.py --cdp-port 9222 --target-host login.microsoftonline.com --cookie-db "...Edge\User Data\Default\Network\Cookies" --out ...\Temp\session_dump.json`, also parented by the hidden PowerShell (PID 7716). Directly targets the Edge cookie DB and `login.microsoftonline.com` (Entra ID/Azure AD SSO domain, where `ESTSAUTH`/`ESTSAUTHPERSISTENT` cookies live). |
| 2026-07-18 14:29:51.002 | 11 (FileCreate) | `python.exe` creates `C:\Users\schen\AppData\Local\Temp\cookies_bak.db` — a copy of the locked Edge Cookies SQLite DB, made so it can be read while the browser holds the lock on the original. |
| 2026-07-18 14:29:52.884 | 11 (FileCreate) | `python.exe` creates `C:\Users\schen\AppData\Local\Temp\session_dump.json` — staging file, presumed (per analyst note, not raw Sysmon content) to hold DPAPI-decrypted `login.microsoftonline.com` session cookies (ESTSAUTH/ESTSAUTHPERSISTENT). |
| 2026-07-18 14:29:55.240 | 3 (NetworkConnect) | `python.exe` connects `10.20.4.117:51501 → 203.0.113.77:443` (HTTPS) — **exfiltration** of `session_dump.json` to an external IP. Analyst note flags `203.0.113.77` as the same IP later seen in an anomalous Azure AD sign-in for this user. |
| 2026-07-18 14:30:12.611 | 5 (ProcessTerminate) | `python.exe` (PID 8840) exits after exfil. Headless `msedge.exe` (PID 9364) and Temp staging files remain on disk for forensic recovery. |

Elapsed time from browser relaunch to exfiltration: ~14 seconds — fast, scripted/automated activity, not manual browsing behavior.

## Key IOCs / Artifacts

**Host / identity**
- Host: `CORP-FIN-WK17` / `CORP-FIN-WK17.contoso.com`
- Internal IP: `10.20.4.117`
- User: `CONTOSO\schen` (local session), LogonId `0x1e3a300`

**Network**
- External C2/exfil IP: `203.0.113.77:443` (HTTPS) — pivot point for Azure AD correlation
- Local CDP endpoint: `127.0.0.1:9222`
- Target domain referenced in script args: `login.microsoftonline.com`

**Processes / hashes**
- `msedge.exe` (legit, signed) — SHA256 `8A1F0C6E2B7D4E9C5A3F6B1D0E4C7A9F2B5D8E1C4A7F0B3D6E9C2A5F8B1D4E7C`, same hash both benign and malicious-flagged launches (i.e., it's the same legitimate binary abused via flags, not a trojanized copy)
- `python.exe` — SHA256 `1B4E7F2A9C6D3E0B5A8F1C4D7E0B3A6F9C2D5E8B1A4F7C0D3E6B9A2F5C8D1E4B`, path `C:\Users\schen\AppData\Local\Programs\Python\Python312\python.exe`
- `powershell.exe` (PID 7716) — hidden-window launcher of both msedge and python.exe; **its own ProcessCreate event is not present in this log** (only appears as ParentImage/ParentCommandLine) — gap to investigate.

**Command lines**
- `msedge.exe --remote-debugging-port=9222 --user-data-dir="C:\Users\schen\AppData\Local\Temp\edg_prof" --headless=new --disable-gpu --no-first-run`
- `powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' -ArgumentList '--remote-debugging-port=9222 ...'"`
- `python.exe C:\Users\schen\AppData\Local\Temp\cdp_cookie_grab.py --cdp-port 9222 --target-host login.microsoftonline.com --cookie-db "C:\Users\schen\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies" --out C:\Users\schen\AppData\Local\Temp\session_dump.json`

**Files**
- `C:\Users\schen\AppData\Local\Temp\cdp_cookie_grab.py` (attacker tool)
- `C:\Users\schen\AppData\Local\Temp\edg_prof\` (throwaway Edge profile dir for headless instance)
- `C:\Users\schen\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies` (source DB, targeted not modified per log)
- `C:\Users\schen\AppData\Local\Temp\cookies_bak.db` (staged copy of cookie DB)
- `C:\Users\schen\AppData\Local\Temp\session_dump.json` (staged/exfiltrated cookie dump — likely contains `ESTSAUTH`/`ESTSAUTHPERSISTENT`)

## Assessment

This is a browser cookie-theft / session-hijacking chain targeting Microsoft Entra ID (Azure AD) SSO cookies, executed on `CORP-FIN-WK17` under user context `CONTOSO\schen`:

1. A hidden PowerShell process relaunched the legitimate, already-running Edge browser with `--remote-debugging-port` and a throwaway profile, enabling remote control via Chrome DevTools Protocol without an obvious visible window to the user.
2. A Python script connected to that CDP port and specifically targeted the Edge `Network\Cookies` SQLite database and `login.microsoftonline.com` — the domain used for Azure AD/Entra ID session cookies.
3. It copied the locked cookie DB to bypass the file lock, extracted/decrypted cookie values (likely via DPAPI, consistent with same-user-context access) into `session_dump.json`.
4. That file was exfiltrated over HTTPS to external IP `203.0.113.77` within seconds of creation.
5. The python process exited, leaving the headless Edge instance and staging artifacts on disk (useful for forensic recovery but also indicates the attacker did not clean up — either time pressure or a scripted/automated tool without a cleanup routine).

**Likely objective:** Steal Azure AD SSO session cookies (ESTSAUTH/ESTSAUTHPERSISTENT) to enable session/token replay and bypass MFA for `CONTOSO\schen`'s cloud identity — classic "pass-the-cookie" / adversary-in-the-browser session hijacking rather than credential theft.

## ATT&CK Mapping

| Technique | ID | Evidence | Confidence |
|---|---|---|---|
| Steal Web Session Cookie | T1539 | Cookie DB copy + targeted extraction of `login.microsoftonline.com` cookies into `session_dump.json` | High |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Hidden PowerShell launching Edge and Python with `-WindowStyle Hidden -NoProfile` | High |
| Command and Scripting Interpreter: Python | T1059.006 | `python.exe cdp_cookie_grab.py` performing the theft | High |
| Browser Session Hijacking / DevTools Protocol abuse | T1185 (also maps to T1539) | `--remote-debugging-port=9222`, headless relaunch, local CDP connection | High |
| Exfiltration Over C2/Web Service (HTTPS) | T1041 | `python.exe` → `203.0.113.77:443` immediately after `session_dump.json` creation | High |
| Masquerading / Legitimate process abuse of msedge.exe | T1036 (loosely; more precisely "living off the land" via signed browser binary) | Same signed `msedge.exe` hash used for both benign and abusive launch — flags, not the binary, are malicious | Medium |
| Credential Access via unsecured/staged files | T1552.001 | `cookies_bak.db` and `session_dump.json` staged in world-readable Temp path | Medium |

## Confidence Summary
- Core narrative (CDP-based cookie theft from Edge, targeting Entra ID SSO cookies, exfil to external IP) — **High confidence**, well-supported by explicit process chain, command lines, file creates, and network connects in the log.
- Exact contents of `session_dump.json` (i.e., that it truly contains ESTSAUTH/ESTSAUTHPERSISTENT) — **Medium confidence**; Sysmon does not capture file contents, this is stated as an analyst annotation/inference, not directly observed telemetry.
- Attribution of `203.0.113.77` as adversary infrastructure and its reuse in the Azure AD sign-in — **High confidence given the analyst note**, but this should be independently verified against the Azure AD sign-in log rather than taken purely on the note's word.

## Gaps / Questions for Correlation and Further Investigation
1. **No ProcessCreate (Event 1) record exists in this log for `powershell.exe` PID 7716 itself** — only seen as a parent reference. Need its own creation event (its parent, command line origin, how it was launched — scheduled task, remote exec, phishing macro, etc.) to determine initial access/execution vector.
2. Correlate `203.0.113.77` and the timestamp `2026-07-18T14:29:55Z` (or shortly after) against `logs/cloud/azuread_signin_logs.json` for a sign-in from `schen`'s UPN (likely `schen@contoso.com` or similar) from that IP — this is the key pivot the analyst note points to.
3. Confirm `schen`'s UPN and any Conditional Access / risk detections tied to that sign-in (impossible travel, unfamiliar sign-in properties, token replay detection) in Azure AD logs.
4. No parent process precedes the PowerShell launch in this log — check for delivery mechanism (email attachment, macro, scheduled task, RMM tool, remote shell) via other EDR/Sysmon Event 1 entries or Windows Security 4688/4104 (PowerShell script block logging) not included in this extract.
5. Was MFA satisfied/bypassed on the follow-on Azure AD sign-in (consistent with cookie/token replay rather than fresh interactive auth with MFA)?
6. Any subsequent Azure AD activity (OAuth consent grants, mailbox rule creation, MFA method changes) after the presumed token replay that would indicate post-hijack objectives.
7. Was `cdp_cookie_grab.py` written to disk by this same PowerShell session (drop mechanism) — worth checking for a FileCreate event for the `.py` file itself, which isn't present in this log excerpt.
