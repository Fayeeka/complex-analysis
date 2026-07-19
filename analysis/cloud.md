# Cloud Log Analysis — Azure AD Sign-In Logs

**File analyzed:** `logs/cloud/azuread_signin_logs.json`
Tenant: `Contoso Ltd` (tenantId `a1b2c3d4-5678-90ab-cdef-1234567890ab`). Data is explicitly marked as synthetic training data with RFC 5737 documentation IP ranges. Only 2 sign-in events are present, covering a single user, Sarah Chen.

## Timeline

| Time (UTC) | Event | Details |
|---|---|---|
| **2026-07-18 13:02:10–13:02:11** | Baseline legitimate sign-in | `sarah.chen@contoso.com` signs into Office 365 Exchange Online via Browser from IP `198.51.100.23`, Chicago, IL, US. Fresh password + Mobile app MFA notification, both succeeded. Device: `CORP-FIN-WK17`, Windows10, Edge 126.0.2592, **compliant/managed, AzureAd-trusted**. `conditionalAccessStatus: success`, risk level `none`. |
| **2026-07-18 14:47:09** | **Anomalous sign-in — session/token replay** | Same user `sarah.chen@contoso.com` signs into Office 365 Exchange Online from IP `203.0.113.77`, Bucharest, Romania. No fresh password or MFA — auth satisfied by **"Previously satisfied" / claim in the token** (i.e., an existing session cookie, not new interactive auth). Device is **unmanaged, non-compliant, no deviceId**, OS = Linux, browser = Chrome 125.0.0.0 (differs entirely from the user's known Windows10/Edge device). `riskLevelAggregated`/`riskLevelDuringSignIn` = **high**, `riskState: atRisk`, `riskEventTypes_v2: ["anomalousToken", "unfamiliarFeatures"]`. `conditionalAccessStatus` still shows **"success"** despite the risk — CA was not re-evaluated against the compliant-device policy because it was a token/cookie replay rather than a full auth flow. |

**Gap between events:** ~1h 45m, but the embedded analyst note ties the IP `203.0.113.77` to a cookie-exfiltration destination observed ~17 minutes earlier in a corresponding endpoint artifact (`logs/windows/sysmon_cookie_theft.json` — not present in this cloud-log directory, but referenced for cross-source correlation).

## Key Indicators / IOCs

- **Affected account:** `sarah.chen@contoso.com` (userId `7d3f9a2c-4b1e-4c6a-8f0d-2e5b8a1c4d7f`, display name "Sarah Chen")
- **Legitimate IP:** `198.51.100.23` (Chicago, US) — baseline
- **Suspicious/attacker IP:** `203.0.113.77` (Bucharest, RO) — session replay source, and per analyst note, matches an exfil destination in endpoint logs
- **Legitimate device:** `CORP-FIN-WK17` (deviceId `e4a7c1f0-8b3d-4a6e-9c2f-5d8b1a4e7c0f`), Windows10, Edge 126.0.2592, compliant+managed, AzureAd trust type
- **Suspicious device:** no deviceId, Linux + Chrome 125.0.0.0, unmanaged/non-compliant, trustType empty
- **App:** Office 365 Exchange Online (`appId`/`resourceId` `00000002-0000-0ff1-ce00-000000000000`)
- **Correlation IDs:** `9b2e6d4a-1f8c-4e3b-a5d7-6c9f2a8b1e40` (legit sign-in), `1a4f7c0d-3e6b-4a9f-8c1d-4e7b0a3f6c9d` (suspicious sign-in)
- **Sign-in IDs:** `5c9e1f3a-2b6d-4e8c-9a1f-3d7b5c9e1f30` (legit), `6d1f2e4b-3c7a-4f9d-8b2e-5a1c8d4f7b62` (suspicious)
- **Risk flags:** `anomalousToken`, `unfamiliarFeatures`
- **Auth method on suspicious sign-in:** `authenticationMethod: "Previously satisfied"`, `authenticationMethodDetail: "Previously satisfied credential"` — strong indicator of session-cookie/token reuse rather than a normal login

## Assessment

This is a textbook **session token / cookie theft and replay** scenario, not a credential-based (password) compromise:

- The 13:02 sign-in is normal: fresh password + MFA, corporate device, known IP/geo — establishes baseline "known good."
- The 14:47 sign-in shows no fresh authentication challenge at all — Entra ID accepted an existing session claim (consistent with theft of the `ESTSAUTH`/`ESTSAUTHPERSISTENT` browser session cookie), from a completely different device (Linux/Chrome vs. Windows/Edge), different unmanaged/non-compliant device posture, and a different country (Romania vs. US) with no plausible travel time between the two events — **impossible travel**.
- Identity Protection correctly flagged this as high risk (`anomalousToken`, `unfamiliarFeatures`), but **Conditional Access still reported "success"** — because the compliant-device/MFA policy was satisfied at original token issuance, and replay of the token was not re-validated against device compliance. This is the exact gap that Continuous Access Evaluation (CAE) and token-binding/token-protection CA policies are designed to close.

## MITRE ATT&CK Mapping

- **T1539 — Steal Web Session Cookie** (primary technique — evidenced by `authenticationMethod: "Previously satisfied"`, no fresh MFA, `anomalousToken` risk flag)
- **T1550.004 — Use Alternate Authentication Material: Web Session Cookie** (replay of stolen cookie to access Exchange Online from attacker infrastructure)
- **T1078.004 — Valid Accounts: Cloud Accounts** (access achieved without triggering new credential/MFA prompts)
- Possible downstream objective: **T1114 — Email Collection** / **Data from Cloud Storage**, given the target resource is Exchange Online (worth checking Azure AD Audit Logs / MailItemsAccessed / mailbox rule changes if available — none present in this file).

**Confidence:** High — the risk signals (`riskLevelAggregated: high`, `anomalousToken`), auth-method anomaly (`Previously satisfied` with no MFA step), device mismatch, and impossible travel all converge consistently on token replay. Confidence is high because these are strong, mutually-corroborating Azure AD Identity Protection signals, not a single weak indicator.

## Correlation Hints for Endpoint Log Analysis

- Search endpoint/Sysmon logs for **outbound connections to `203.0.113.77`** around/before `2026-07-18T14:30:00Z`–`14:47:09Z` (the analyst note references a specific file, `logs/windows/sysmon_cookie_theft.json`, describing cookie exfiltration ~17 minutes prior — confirm this file's timestamps line up).
- Look for browser credential/cookie theft tooling (e.g., access to `%LOCALAPPDATA%\...\Cookies`/`Network` SQLite DB, LSASS access, or known cookie-stealer malware families) on host `CORP-FIN-WK17` (deviceId `e4a7c1f0-8b3d-4a6e-9c2f-5d8b1a4e7c0f`) tied to user `sarah.chen@contoso.com`, particularly in the window between the 13:02 legitimate sign-in and 14:47 replay.
- Correlate username `sarah.chen@contoso.com` / display name "Sarah Chen" across both sources.
- Cross-reference IP `203.0.113.77` as both the Azure AD sign-in source and any C2/exfil destination in endpoint network logs.
- Check for any process activity indicating browser automation/headless Chrome on Linux consistent with replaying the stolen cookie (the sign-in device fingerprint shows Linux + Chrome 125.0.0.0, unmanaged).

## Note on Data Scope
This log file contains only 2 sign-in events for a single user/session pair — there is no broader dataset here (no audit logs for role/group changes, app consent grants, or service principal modifications, despite the task description mentioning those categories). If a corresponding Azure AD **audit log** file exists elsewhere in the repo, it should be reviewed separately for privilege-escalation activity following this token theft (e.g., mailbox rule creation, OAuth consent grants, or delegate access changes) — none of that data is present in `logs/cloud/azuread_signin_logs.json`.
