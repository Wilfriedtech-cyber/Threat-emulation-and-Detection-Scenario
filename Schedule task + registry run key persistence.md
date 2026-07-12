# Persistence via Scheduled Task & Registry Run Key

**Adversary emulation and detection engineering in a self-built SOC homelab.**

---

## Objective

Emulate an attacker establishing multi-vector persistence on a compromised Windows host using both a scheduled task and a registry run key. Detect the attacker footprint in Splunk and understand what fields those attacks leverage for better detection tuning.

| Stage | Technique | ATT&CK ID |
|-------|-----------|-----------|
| Scheduled Task Creation | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Registry Run Key Write | Boot or Logon Autostart: Registry Run Keys | T1547.001 |

---

## Step 1 — Create Ability 1 (Scheduled Task)

In Caldera UI → **Abilities → + Add Ability**

| Field | Value |
|---|---|
| Name | `Persistence via Scheduled Task` |
| Tactic | `persistence` |
| Technique ID | `T1053.005` |
| Technique Name | `Scheduled Task/Job: Scheduled Task` |
| Platform | `windows` |
| Executor | `psh` |

Command:
```
schtasks /create /tn "WindowsUpdate" /tr "powershell.exe -WindowStyle Hidden -File C:\beacon.ps1" /sc onlogon /ru SYSTEM
```

<img width="1120" height="723" alt="image" src="https://github.com/user-attachments/assets/8799ffd5-d968-49b8-972e-58f78e700c28" />

<img width="1086" height="698" alt="image" src="https://github.com/user-attachments/assets/6f855e9a-c765-442a-b15e-594803302c50" />

---

## Step 2 — Create Ability 2 (Registry Run Key)

In Caldera UI → **Abilities → + Add Ability**

| Field | Value |
|---|---|
| Name | `Persistence via Registry Run Key` |
| Tactic | `persistence` |
| Technique ID | `T1547.001` |
| Technique Name | `Boot or Logon Autostart: Registry Run Keys` |
| Platform | `windows` |
| Executor | `psh` |

Command:
```
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "powershell.exe -File C:\beacon.ps1" /f
```
<img width="1104" height="706" alt="image" src="https://github.com/user-attachments/assets/1889b3a5-dca2-44b3-89f2-9d0ccbe67c01" />

<img width="1099" height="703" alt="image" src="https://github.com/user-attachments/assets/2a76b641-6e12-4886-99fe-62512b32d3ba" />

---

## Step 3 — Build the Adversary Profile

1. **Adversaries → New Profile**
2. Name: `Scenario 2 - Persistence`
3. Add abilities in this order: **Scheduled Task → Registry Run Key**
4. Save

<img width="1672" height="744" alt="image" src="https://github.com/user-attachments/assets/a2c40a76-0663-4e2e-b93c-ebf480c6ef34" />

---

## Step 4 — Run the Operation

1. **Operations → New Operation**
2. Select profile: `Scenario 2 - Persistence`
3. Select agent: Win10 Client agent
4. Click **Start**
5. Wait for both abilities to go green
6. Note the timestamp — scope your Splunk searches to this window
7. Export the operation graph when complete

Both abilities ran successfully.

<img width="889" height="721" alt="image" src="https://github.com/user-attachments/assets/c33cfe06-93d5-4047-9071-9761dde23622" />
As we can see the operation was successful 
<img width="1885" height="857" alt="image" src="https://github.com/user-attachments/assets/baa7b28f-e3bc-414f-9ea8-2e13ebf25075" />

---

## Step 5 — Detection in Splunk

While performing threat hunting I was able to use those queries to catch the simulation, which were then saved as alerts.

### Detection 1 — Scheduled Task Creation
`Persistence - Scheduled Task Created - T1053.005`

Sysmon EventID 1 catches `schtasks.exe` spawning with `/create` in the command line. The `CommandLine` field reveals the full task definition — name, trigger, and payload path.

```spl
index=* EventCode=1 Image="*schtasks.exe" CommandLine="*/create*"
| table _time, host, User, CommandLine, ParentImage
| sort _time
```

<img width="1651" height="883" alt="image" src="https://github.com/user-attachments/assets/eb728720-53d9-4b3a-8f1f-31b5f404216e" />


### Detection 2 — Registry Run Key Write
`Persistence - Registry Run Key Modified - T1547.001`

Sysmon EventID 13 fires the moment any process writes to the Run key. The `TargetObject` field shows the exact registry path and `Details` shows the value written — in this case the full PowerShell beacon command.

```spl
index=* EventCode=13 TargetObject="*CurrentVersion\\Run*"
| table _time, host, Image, TargetObject, Details
| sort _time
```

<img width="1521" height="926" alt="image" src="https://github.com/user-attachments/assets/6a1e92b2-3044-45b6-ae3c-03d68bc9cf0a" />

---

## Step 6 — Save as Alerts

For each query → **Save As → Alert**:

| Alert Title | Technique |
|---|---|
| `Persistence - Scheduled Task Created - T1053.005` | T1053.005 |
| `Persistence - Registry Run Key Modified - T1547.001` | T1547.001 |

Alert settings for each:
- Alert type: **Real-time**
- Trigger: **Per Result**
- Throttle: ✅ field `host` → 60 minutes
- Action: **Add to Triggered Alerts** → severity **High**

<img width="1518" height="869" alt="image" src="https://github.com/user-attachments/assets/9d7e3001-447f-4f92-ae76-8ebe817b5235" />

<img width="1517" height="876" alt="image" src="https://github.com/user-attachments/assets/1b2a8e48-df33-4a44-a32c-c8a1e64904ee" />

---

## Step 7 — Re-run + Capture Proof

Re-run the operation → **Activity → Triggered Alerts** → screenshot all alerts firing.

> **Note:** the scheduled task ability failed on the second run because the task `WindowsUpdate` already existed from the first run. This is expected behavior — the alert still fired on the original creation event.

<img width="1669" height="794" alt="image" src="https://github.com/user-attachments/assets/c5b1717b-8789-462c-94ef-5b8f9ff93035" />

<img width="998" height="419" alt="image" src="https://github.com/user-attachments/assets/f50c6928-c094-42e8-b82f-e1e9523a3448" />

<img width="1660" height="913" alt="image" src="https://github.com/user-attachments/assets/7ab2de80-1071-452e-a690-2f74045cad0d" />

---

## Results

| Detection | Technique | Source | Result |
|-----------|-----------|--------|--------|
| Scheduled Task Creation | T1053.005 | Sysmon `EventID 1` | ✅ Detected |
| Registry Run Key Write | T1547.001 | Sysmon `EventID 13` | ✅ Detected |

---

## Lessons Learned

- **schtasks.exe spawning PowerShell is worth investigating.** It can be a legitimate admin scheduling a task or an attacker using living-off-the-land binaries for persistence — either way it deserves a look.
- **Sysmon EventID 13 is non-negotiable for registry persistence detection.** The registry Run key (`HKCU\...\CurrentVersion\Run`) executes automatically every time the user logs in. Without Sysmon 13 there is no native Windows event that tells you something was written there — you would be completely blind to this persistence mechanism.

---

*Built in an isolated SOC homelab against dummy test data. All techniques mapped to MITRE ATT&CK.*
