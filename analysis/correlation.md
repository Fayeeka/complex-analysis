# Multi-Source Correlation — Session-Cookie Theft & Pass-the-Cookie Replay

**Sources correlated:**
- `analysis/endpoint.md` — Sysmon, host `CORP-FIN-WK17` (`logs/windows/sysmon_cookie_theft.json`)
- `analysis/cloud.md` — Azure AD sign-in logs, tenant Contoso Ltd (`logs/cloud/azuread_signin_logs.json`)

**Scenario:** Session-cookie theft on `CORP-FIN-WK17` → pass-the-cookie replay into Exchange Online for `sarah.chen@contoso.com`.
**Note:** Both source files are labeled synthetic/training data (RFC 5737 documentation IPs). Analysis is written as if investigating a real incident.

---

## 1. Timeline Alignment (UTC)

| Time | Source | Event |
|---|---|---|
| 13:02:10–13:02:11 | Cloud | **Legit sign-in** — `sarah.chen@contoso.com` into Exchange Online from `198.51.100.23` (Chicago), Windows10/Edge, compliant device, fresh password + MFA. Baseline "known good." |
| 13:05:12 | Endpoint | Baseline: `msedge.exe` launched normally by `schen` (parent `explorer.exe`). Matches the legit browser session above. |
| 14:29:41 | Endpoint | **Attack begins** — hidden PowerShell (PID 7716) relaunches Edge with `--remote-debugging-port=9222 --headless=new` (CDP enabled). |
| 14:29:50 | Endpoint | `python.exe` attaches to `127.0.0.1:9222`, runs `cdp_cookie_grab.py` targeting `login.microsoftonline.com` cookies. |
| 14:29:51–52 | Endpoint | Copies locked Edge Cookies DB → `cookies_bak.db`, stages `session_dump.json`. |
| 14:29:55 | Endpoint | **Exfiltration** — `session_dump.json` sent via HTTPS to `203.0.113.77:443`. |
| 14:30:12 | Endpoint | `python.exe` exits; headless Edge + staging files left on disk. |
| ~17 min gap | — | Attacker moves stolen cookie to their own infrastructure. |
| 14:47:09 | Cloud | **Replay** — sign-in as `sarah.chen@contoso.com` from `203.0.113.77` (Bucharest), Linux/Chrome, unmanaged device, **no fresh MFA** (`"Previously satisfied"` token). Risk = high (`anomalousToken`, `unfamiliarFeatures`). |

The endpoint theft (14:29:55) and cloud replay (14:47:09) bracket a ~17-minute window — tight and consistent with a single automated operation.

---

## 2. User Correlation

One identity, two representations:
- **Endpoint:** `CONTOSO\schen` (local session, LogonId `0x1e3a300`) on `CORP-FIN-WK17`
- **Cloud:** `sarah.chen@contoso.com` (userId `7d3f9a2c-4b1e-4c6a-8f0d-2e5b8a1c4d7f`, "Sarah Chen")

**On endpoint** Sarah is the *victim context* — the theft runs under her token, but the initiating PowerShell is not her interactive action (hidden window, no explorer parentage). **In cloud** her identity is *impersonated* via the stolen session — the 14:47 sign-in is the attacker, not her. The compliant device `CORP-FIN-WK17` appears on both sides (endpoint host = deviceId `e4a7c1f0-8b3d-4a6e-9c2f-5d8b1a4e7c0f` in the legit cloud sign-in), confirming the same machine is the theft origin.

---

## 3. IP Correlation

**`203.0.113.77` is the pivot linking both sources:**
- Endpoint: exfil **destination** at 14:29:55 (`10.20.4.117 → 203.0.113.77:443`)
- Cloud: sign-in **source** at 14:47:09 (Bucharest, RO)

The attacker exfiltrated the cookie to an IP, then authenticated *from that same IP* — the strongest single correlation in the dataset. `198.51.100.23` (Chicago) appears only in cloud as Sarah's legitimate baseline.

---

## 4. Attack Chain

- **Initial access — UNKNOWN.** No ProcessCreate event exists for the hidden PowerShell (PID 7716); it only appears as a parent. The delivery vector (phishing macro, scheduled task, RMM, remote shell) is not in these logs. This is the biggest evidentiary hole.
- **Actions on endpoint (14:29:41–14:30:12):** Hidden PowerShell → CDP-enabled headless Edge → Python (`cdp_cookie_grab.py`) attaches to CDP, copies the locked cookie DB, extracts/decrypts (likely DPAPI, same-user context) the `login.microsoftonline.com` SSO cookies (`ESTSAUTH`/`ESTSAUTHPERSISTENT`) into `session_dump.json`. ~14 seconds end-to-end — scripted.
- **Pivot to cloud:** `session_dump.json` exfiltrated to `203.0.113.77`; ~17 min later that cookie is replayed from the same IP. Conditional Access returned "success" because token replay wasn't re-evaluated against device compliance — MFA effectively bypassed.
- **Ultimate objective:** Access to **Exchange Online** as Sarah Chen — likely email collection (T1114). Not directly observed in these logs.

**ATT&CK spine:** T1059.001/.006 (PowerShell/Python) → T1185 / T1539 (browser session hijack via CDP, steal web session cookie) → T1041 (exfil over HTTPS) → T1550.004 (use stolen web session cookie) → T1078.004 (valid cloud account) → *likely* T1114 (email collection).

---

## 5. Confidence Assessment

**High confidence:**
- The cookie-theft chain on the endpoint (explicit process, command-line, file, and network telemetry).
- The cloud sign-in was token replay, not credential login (`"Previously satisfied"`, no MFA, high risk, device mismatch, impossible travel).
- `203.0.113.77` links the two events — exfil target = replay source.
- Single victim identity across both sources.

**Uncertain / lower confidence:**
- **Contents** of `session_dump.json` — Sysmon doesn't capture file bodies; that it holds ESTSAUTH cookies is inference (Medium).
- **Initial access vector** — entirely absent (see Gaps).
- **Post-replay objective** — Exchange Online was accessed, but no mailbox actions (rules, MailItemsAccessed, OAuth consents) are in scope, so actual data theft is unconfirmed.
- The ~17-min pivot rests partly on analyst annotations embedded in the logs rather than pure raw telemetry — worth independently confirming timestamps line up.

---

## 6. Missing Logs / Collection Gaps

1. **PowerShell 4104 script-block logging / Security 4688** — to recover PID 7716's own creation, its parent, and the delivery mechanism (the #1 gap).
2. **FileCreate for `cdp_cookie_grab.py`** — how/when the tool was dropped.
3. **Azure AD Audit logs** — mailbox rule creation, OAuth consent grants, delegate/MFA-method changes after 14:47 (post-hijack objectives).
4. **Exchange / M365 unified audit (MailItemsAccessed, message sends)** — to confirm what the attacker did with the session.
5. **Proxy/firewall/NetFlow for `203.0.113.77`** — bytes transferred (exfil volume) and any other hosts talking to that IP.
6. **EDR memory/DPAPI telemetry** — confirm decryption of the cookie blob.

---

## Recommended Immediate Response

- Revoke Sarah Chen's Entra sessions/refresh tokens (invalidate the stolen cookie).
- Force password reset + MFA re-registration.
- Isolate `CORP-FIN-WK17` and preserve the Temp staging artifacts for forensics.
- Block `203.0.113.77` at egress and identity layers.
- Enable token protection (token binding) and Continuous Access Evaluation (CAE) to close the replay gap that let CA report "success" on a stolen cookie.
