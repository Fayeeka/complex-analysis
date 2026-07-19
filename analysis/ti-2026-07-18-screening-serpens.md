---
source_url: https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/
extraction_date: 2026-07-18
title: "Tracking Iran-Nexus APT Screening Serpens"
publisher: Unit 42 (Palo Alto Networks)
---

# Threat Intel Analysis: Screening Serpens (Iran-nexus APT)

## Threat Overview

- **Actor / campaign name:** Screening Serpens (aka UNC1549, Smoke Sandstorm, Iranian Dream Job)
- **Attribution:** Iran-nexus APT, cyberespionage aligned with Iranian intelligence objectives. Active since at least 2022.
- **Targeted industries:** Aerospace, defense manufacturing, telecommunications, and broadly technology-sector professionals (via job-seeker social engineering).
- **Targeted regions:** U.S., Israel, United Arab Emirates, and two additional (unnamed) Middle Eastern entities. Historically Middle East-focused; expanded into Western Europe in late 2025 (per Check Point reporting).
- **Time period covered:** Mid-February 2026 through April 2026, timed closely with a regional Middle East conflict that began Feb. 28, 2026. Report published ~May 2026.
- **Malware families:** Two new families identified — **MiniUpdate** (new) and **MiniJunk V2** (evolved from previously documented MiniJunk). Six new RAT variants total across both families.
- **Notable tradecraft evolution:** First observed fusion of standard DLL sideloading with **AppDomainManager hijacking** to disable .NET CLR security telemetry (ETW, strong-name signature validation, publisher policy redirection) via a legitimate application config file, achieving pre-Main() code execution before the host app initializes.

## TTPs (MITRE ATT&CK Mapping)

| ATT&CK ID | Technique | How Observed | Confidence |
|---|---|---|---|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Phishing: Spearphishing Attachment | Fake job requisition PDFs + nested `Hiring Portal.zip` archive delivered as an outer ZIP impersonating a global air carrier's hiring process | High |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Phishing: Spearphishing Link | Lookalike video-conferencing domain (`hxxps://[redacted].live/meeting/...`) and a spoofed/misspelled recruitment URL (`.../career/recreuitment/...`) that redirected to a file-sharing/ONLYOFFICE-hosted payload | High |
| [T1656](https://attack.mitre.org/techniques/T1656/) | Impersonation | Lures impersonate a global air carrier, a popular video-conferencing platform, and a well-known employment website to build trust with targets | High |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | Victim manually extracts and runs `setup.exe` / `Setup.exe` from the delivered archive | High |
| [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | Hijack Execution Flow: DLL Side-Loading | Core execution chain across both families: legitimate signed binaries (`setup.exe`, `SoftwareLicencing.exe`) load attacker DLLs (`InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`, `unbcl.dll`, `Connection.dll`) | High |
| [T1574.014](https://attack.mitre.org/techniques/T1574/014/) | Hijack Execution Flow: AppDomainManager | Malicious `.config` file uses `<probing privatePath>` + custom `AppDomainManager` type (`MyAppDomainManager`) for Pre-Main() execution; explicitly named and cited to ATT&CK in the report | High |
| [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | Subvert Trust Controls: Code Signing Policy Modification | `<bypassTrustedAppStrongNames enabled="true"/>` and `<publisherPolicy apply="no"/>` directives disable strong-name/signature validation for the sideloaded DLL | High |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | `<etwEnable enabled="false"/>` natively disables Event Tracing for Windows before the CLR loads, blinding EDR telemetry without memory patching or API hooking | High |
| [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information | Custom two-step cipher (byte reversal + ROT13) to decrypt 9 config strings; XOR (single-byte key `0x8A`) and Mixed Boolean-Arithmetic decryption of C2 URLs/User-Agent in Connection.dll and MiniJunk V2 | High |
| [T1027.001](https://attack.mitre.org/techniques/T1027/001/) | Obfuscated Files or Information: Binary Padding | MiniJunk V2's `.rdata` packed with thousands of repeating junk strings (every 0x1E50 bytes) to inflate binary to ~12MB, evading sandbox file-size limits and string-extraction tooling | High |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task | Daily 09:30 local-time task for MiniUpdate persistence; logon-triggered `WindowsSecurityUpdate` task (removable/reinstallable); `Synchronize OS` task for MiniJunk V2 | High |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Masquerading: Match Legitimate Name or Location | Files renamed/staged as `update.exe`, `update.exe.config`, `SoftwareLicencing.exe`; hidden install path under legit app's AppData folder; scheduled task named `WindowsSecurityUpdate`/`Synchronize OS` | High |
| [T1620](https://attack.mitre.org/techniques/T1620/) | Reflective Code Loading | MiniUpdate opcode loads arbitrary DLLs directly into memory and invokes exported functions | Medium |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Command and Scripting Interpreter: Windows Command Shell | Arbitrary shell command execution via `cmd.exe /c` | High |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | HTTP GET polling (`/agent/poll`) and POST beaconing to Azure-hosted C2 domains with spoofed browser User-Agent strings | High |
| [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | Data Encoding: Standard Encoding | Command dispatcher processes a Base64-decoded binary command format | Medium |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Payload delivery via third-party file-sharing (Filemail) and ONLYOFFICE DocSpace-hosted archives; C2 "update"/"download subsequent payloads" endpoints | Medium-High |
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | File uploads to C2, including chunked-upload capability added in the April MiniUpdate variants for stealthier exfil of large files | High |
| [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery | Enumerates and can terminate running processes | Medium |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Abuse Elevation Control Mechanism: Bypass User Account Control | MiniUpdate opcode requests UAC elevation | Medium |
| [T1497.003](https://attack.mitre.org/techniques/T1497/003/) | Virtualization/Sandbox Evasion: Time Based Evasion | Connection.dll hard-codes a validity check requiring execution after March 27, 2026 13:30 UTC before running | High |
| [T1497](https://attack.mitre.org/techniques/T1497/) | Virtualization/Sandbox Evasion | Parent-process check (must be `svchost.exe`) and process-name check (`update.exe`) to detect direct/sandbox execution and silently terminate otherwise | High |

**Resource development (not directly simulatable via endpoint atomics, noted for context):**
- [T1583.001](https://attack.mitre.org/techniques/T1583/001/) Acquire Infrastructure: Domains — 3–5 unique Azure-hosted (`azurewebsites.net`) C2 domains per target/variant, rotated and themed to impersonate health, financial, and tech-sector brands.
- [T1608.001](https://attack.mitre.org/techniques/T1608/001/) Stage Capabilities: Upload Malware — payloads staged on ONLYOFFICE DocSpace and Filemail file-sharing services.
- [T1587.001](https://attack.mitre.org/techniques/T1587/001/) Develop Capabilities: Malware — six new RAT variants developed/iterated over Feb–Apr 2026; MiniUpdate payload digitally signed using a likely stolen/impersonated software-company signature.

## Indicators of Compromise

**Domains**
```
licencemanagers.azurewebsites[.]net
LicenceSupporting.azurewebsites[.]net
PeerDistSvcManagers.azurewebsites[.]net
ThemesManagers.azurewebsites[.]net
ThemesProviderManagers.azurewebsites[.]net
docspace-y4cumb.onlyoffice[.]com
NanoMatrix.azurewebsites[.]net
QuantumWeave.azurewebsites[.]net
ElementShift.azurewebsites[.]net
business-startup[.]org
business-startup.azurewebsites[.]net
Businessstartup.azurewebsites[.]net
app[redacted][.]live
buisness-centeral.azurewebsites[.]net
buisness-centeral-transportation.azurewebsites[.]net
Buisness-centeral-transportation[.]com
docspace-twpf0e.onlyoffice[.]com
PremierHealthAdvisory[.]com
PremierHealthAdvisory.azurewebsites[.]net
Premier-HealthAdvisory.azurewebsites[.]net
Ramiltonsfinance[.]com
Ramiltonsfinance.azurewebsites[.]net
Ramiltons-finance.azurewebsites[.]net
```

**URLs**
```
hxxps[:]//docspace-y4cumb.onlyoffice[.]com/storage/files/root/folder_3602000/file_3601577/v1/content.zip[...]
hxxps[:]//app[redacted][.]live/meeting/edcdba624ddb43c2a1dcf334aa493068
hxxps[:]//docspace-twpf0e.onlyoffice[.]com/storage/files/root/folder_3765000/file_3764519/v1/content.zip?filename=remote.[REDACTED].zip
hxxps[:]//2117.filemail[.]com/api/file/get?filekey=T0EnWQ6NugHkW_kLfDxPBEw_um6NSkg9ZwNRQ_5lrKrLLUo35pV8m3TKv1LqF3zZzdUm
```

**File paths / artifacts**
```
UpdateChecker.dll        (MiniUpdate payload; internal name references "UpdateChecker")
InitInstall.dll          (MiniUpdate stage-1 loader)
Updater.dll              (MiniUpdate stage-2)
setup.exe / update.exe   (renamed sideloading host)
UpdateConfig.xml / update.exe.config / setup.exe.config
%LOCALAPPDATA%\<video-conferencing-app>\bin\update\  (staging directory)
uevmonitor.dll           (MiniJunk V2 loader)
unbcl.dll                (MiniJunk V2 payload / decoy)
Connection.dll           (MiniJunk V2 U.S. campaign RAT payload)
SoftwareLicencing.exe    (renamed legitimate MS setup binary used for sideloading)
Hiring Portal.zip / Portal.zip / Portable platform.zip / Portable Platform.zip  (lure archives)
Scheduled task: "WindowsSecurityUpdate" (logon trigger)
Scheduled task: "Synchronize OS"
Scheduled task: daily 09:30 local time (unnamed in report)
```

**SHA256 Hashes**

| Hash | Family / Campaign | Description |
|---|---|---|
| `44f4f7aca7f1d9bfdaf7b3736934cbe19f851a707662f8f0b0c49b383e054250` | MiniUpdate – US | Initial archive file |
| `332ba2f0297dfb1599adecc3e9067893e7cf243aa23aedce4906a4c480574c17` | MiniUpdate – US | Hiring Portal.zip |
| `0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864` | MiniUpdate – US | UpdateChecker.dll |
| `38bd137c672bd58d08c4f0502f993a6561e2c3411773d1ae57ee0151a0a9d11d` | MiniUpdate – Israel | Initial archive file |
| `d4a7e9f107fe40c1a5d0139c6c6e25bf6bf57f61feff090bee28f476bb3cc3c2` | MiniUpdate – Israel | UpdateChecker.dll |
| `bc3b44154518c5794ce639108e7b9c5fecb0c189607a26de1aaed518d890c7ad` | MiniUpdate – UAE | UpdateChecker.dll |
| `74882085db2088356ed7f72f01e0404a0a98cda88ef56fb15ce74c1f36b26d27` | MiniUpdate – Middle East | (unlabeled) |
| `9cf029daca89523d917dafed0568d11d00e45ec96b5b90b4a1f7fd4018c7da84` | MiniJunk V2 – Middle East | uevmonitor.dll |
| `b19e06da580cf91691eda066ac9ee4b09c6e5dc26c367af12660fe1f9306eec4` | MiniJunk V2 – Middle East | unbcl.dll |
| `8808c794c24367438f183e4be941876f1d3ecd0c8d2eb43b10d2380841d2283b` | MiniJunk V2 – US | Portable Platform.zip |
| `43dc62cef52ebdd69e79f10015b3e13890f26c058325c0ff139c70f8d8eadcfa` | MiniJunk V2 – US | Connection.dll |
| `9e4a658e6d831c9e9bdfe11884a75b7c64812ed0a80e8495ddf6b316505acac1` | MiniJunk V2 – US | unbcl.dll |

**Other identifiers**
- User-Agent (MiniUpdate): `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36`
- User-Agent (MiniJunk V2 – Middle East sample): `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0`
- MiniUpdate C2 endpoint: `/agent/poll`
- MiniJunk V2 C2 endpoints: `/api/app/check`, `/api/app/update`, `/api/app/comment`
- XOR key (Connection.dll): single-byte `0x8A`
- Junk-string repeat interval (MiniJunk V2 `.rdata`): every `0x1E50` bytes

## Simulation Plan (Atomic Red Team)

Atomic test availability was verified against the current `redcanaryco/atomic-red-team` repository (`atomics/` index) at time of writing. Priority = high-confidence technique **and** available atomic test(s).

### Priority 1 — High confidence + atomics available

| Technique | Atomic Tests Available | Suggested Test(s) |
|---|---|---|
| T1566.001 Spearphishing Attachment | 2 tests | #1 Download Macro-Enabled Phishing Attachment |
| T1566.002 Spearphishing Link | 1 test | #1 Paste and run technique |
| T1204.002 User Execution: Malicious File | 13 tests | #9 Office Generic Payload Download; #10 LNK Payload Download (closest analogues to archive-delivered installer execution) |
| T1053.005 Scheduled Task/Job | 12 tests | #1 Scheduled Task Startup Script; #2 Scheduled Task Local (map to the daily 09:30 and logon-triggered persistence tasks) |
| T1036.005 Masquerading: Match Legitimate Name or Location | 3 tests | #2 Masquerade as a built-in system executable (closest analogue to `update.exe`/`SoftwareLicencing.exe` renaming) |
| T1027.001 Binary Padding | 2 tests | #1/#2 Pad Binary to Change Hash (Linux/macOS only — see gap note below for Windows) |
| T1140 Deobfuscate/Decode Files or Information | 11 tests | #3 Base64 decoding with Python; #10 XOR decoding and command execution using Python (closest analogue to the custom cipher/XOR routines) |
| T1059.003 Windows Command Shell | 6 tests | #1 Create and Execute Batch Script; #3 Suspicious Execution via Windows Command Shell |
| T1071.001 Web Protocols | 3 tests | #1 Malicious User Agents - PowerShell (validates detection of anomalous/spoofed UA beaconing) |
| T1105 Ingress Tool Transfer | 39 tests | #7 Certutil download; #10 PowerShell Download; #18 Curl Download File |
| T1057 Process Discovery | 9 tests | #2 Process Discovery - tasklist |
| T1548.002 Bypass User Account Control | 27 tests | #3 Bypass UAC using Fodhelper; #8 Disable UAC using reg.exe |
| T1497.003 Time Based Evasion | 1 test | #1 Delay execution with ping |

### Priority 2 — High confidence, but no current atomic test (gaps)

These are core to what makes this campaign notable — especially the AppDomainManager/CLR-hijack chain — and represent the most detection-value-add if your team builds custom simulations:

- **T1574.014 AppDomainManager** — **no atomic test exists** in the public repo. This is the headline technique of the report (manipulating a `.config` file's `<probing privatePath>` + custom `AppDomainManager` type for Pre-Main() code execution). Recommend building a custom detonation: a signed .NET host app + companion `.config` with `<probing privatePath="."/>` loading a benign test assembly, to validate detection of local sideloading via CLR config manipulation.
- **T1553.002 Code Signing Policy Modification** — **no atomic test exists**. Recommend a custom test replicating `<bypassTrustedAppStrongNames enabled="true"/>` and `<publisherPolicy apply="no"/>` directives in an app config to validate detection of native strong-name/signature-check suppression.
- **T1562.001 Disable or Modify Tools** — **no atomic tests currently exist in the repo for any T1562 subtechnique** (notable general gap, not specific to ETW). Recommend a custom test toggling `<etwEnable enabled="false"/>` in a .NET app config, or using an existing ETW-session-disabling PowerShell snippet, to validate EDR coverage of native ETW suppression via config rather than in-memory patching.
- **T1574.002 DLL Side-Loading** — **no atomic test currently in the repo** (folder removed/absent). This is the foundational execution technique for both malware families. Recommend a custom test: place an attacker-controlled DLL matching an expected import name alongside a legitimate signed executable known to be vulnerable to sideloading, and confirm load order/detection.
- **T1620 Reflective Code Loading** — 1 test exists (WinPwn/Mimikatz reflective load) but it's a heavyweight, tool-specific test; consider a lighter custom PoC reflecting a benign DLL to validate detection without deploying an actual credential-theft tool.

### Priority 3 — Medium confidence / supporting techniques

- T1132.001 Data Encoding (Base64 command dispatcher) — covered indirectly by T1140 tests above; no dedicated atomic.
- T1041 Exfiltration Over C2 Channel — no dedicated atomics folder found; consider pairing with T1071.001 web-protocol tests plus a scripted chunked-upload PoC to a test listener.
- T1497 Virtualization/Sandbox Evasion (parent-process/svchost check) — no direct atomic; closest is T1497.003 (time-based) above. A custom test validating parent-process-name checks (`svchost.exe`) before payload execution would close this gap.
- T1656 Impersonation — no ATT&CK-technique-specific atomics (this is a narrative/lure technique, not something typically simulated on an endpoint).

### Recommended simulation order (given high confidence + atomic availability + narrative centrality of the campaign)

1. T1566.001 / T1566.002 (initial access lure delivery)
2. T1204.002 (user execution of dropped installer)
3. T1053.005 (scheduled task persistence — both daily and logon-triggered variants)
4. T1036.005 (masquerading of staged binaries)
5. Custom T1574.002 + T1574.014 + T1553.002 + T1562.001 chain (the defining AppDomainManager hijack sequence — build this as a linked custom detonation since no atomics exist for any of these four techniques individually)
6. T1071.001 + T1105 (C2 beaconing / payload retrieval)
7. T1548.002, T1057, T1497.003 (secondary capabilities)

## Additional References

- [Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/) — Check Point
- [Iranian "Dream Job" Campaign](https://www.clearskysec.com/irdreamjob24/) — ClearSky
- [Frontline Intelligence: Analysis of UNC1549 TTPs, Custom Tools, and Malware Targeting the Aerospace and Defense Ecosystem](https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense) — Google Cloud Blog
- [When Cats Fly: Suspected Iranian Threat Actor UNC1549 Targets Israeli and Middle East Aerospace and Defense Sectors](https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-unc1549-targets-israel-middle-east) — Google Cloud Blog
- [Smoke Sandstorm: Nation-State Actors](https://www.microsoft.com/en-us/security/security-insider/threat-landscape/smoke-sandstorm) — Microsoft Security Insider
- [Global Incident Response Report 2026: Screening Serpens](https://www.paloaltonetworks.com/resources/research/unit-42-incident-response-report#threats-and-trends-4) — Unit 42 | Palo Alto Networks
