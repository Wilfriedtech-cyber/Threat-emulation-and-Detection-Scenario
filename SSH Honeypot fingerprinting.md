#  Honeypot Attacker Fingerprinting via Cowrie SSH

**Real honeypot telemetry collection and detection engineering in a self-built SOC homelab.**

Simulated a real-world attacker discovering and brute-forcing a Cowrie SSH honeypot, then documented their post-authentication enumeration behavior. Unlike the other scenarios, this one uses **real honeypot telemetry** rather than Caldera emulation — Cowrie logs every connection, credential attempt, and command typed by the attacker.

---

## Objective

Simulate an attacker brute-forcing a publicly exposed SSH honeypot, logging in with a weak credential, and running enumeration commands — then detect and fingerprint every stage of that behavior in Splunk.

| Stage | Technique | ATT&CK ID |
|-------|-----------|-----------|
| SSH Brute Force | Brute Force | T1110 |
| Post-Auth Command Execution | Command and Scripting Interpreter | T1059 |
| System Enumeration | System Information Discovery | T1082 |

---

## Lab Architecture

| Zone | Host | Role |
|------|------|------|
| Public | Kali | Attacker — runs Hydra + SSH client |
| Perimeter | pfSense | Port forwards SSH traffic to the honeypot |
| Private | Cowrie / DVWA | SSH honeypot — **the target** |
| Private | Splunk | SIEM — ingests Cowrie JSON logs |
| Infra | ESXi | Hypervisor |


## The Attack — Kali Linux

No Caldera needed for this scenario. Kali attacks the honeypot directly — this is how real attackers interact with internet-exposed SSH services.

First as every attack stage I will be performing a quick enumeration.


### Step 1 — SSH Brute Force (T1110)
Launch Hydra against the honeypot using the rockyou wordlist. Cowrie accepts weak credentials by design so a hit comes quickly.

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.16.32.251 -t 4 -V
```

Note the credential that succeeds — you'll use it to log in.

<img width="1913" height="958" alt="image" src="https://github.com/user-attachments/assets/bf322dd1-d158-4d14-b06c-a847d1546d42" />


### Step 2 — Log In with Caught Credential
```bash
ssh root@192.16.32.251
```
You're now inside the Cowrie fake shell. The attacker has no idea it's a honeypot.
<img width="1907" height="920" alt="image" src="https://github.com/user-attachments/assets/37121271-0ded-40f1-ae06-53587b71bd1f" />


### Step 3 — Post-Auth Enumeration (T1059 + T1082)
Run standard attacker enumeration commands. Cowrie logs every single one:

```bash
whoami
id
uname -a
cat /etc/passwd
ifconfig
```
<img width="1911" height="918" alt="image" src="https://github.com/user-attachments/assets/84ac20a0-d0f2-40ae-9926-5b95b028c019" />


## Detection Engineering — Splunk


### 1. Brute Force Detection — `Brute Force - SSH Login Failures - T1110`

Counts failed login attempts per source IP. A high count from a single IP in a short window is the brute-force signature.

```spl
index=main eventid="cowrie.login.failed"
| stats count by src_ip, username
| sort -count
```

<img width="1392" height="884" alt="image" src="https://github.com/user-attachments/assets/e369f065-343d-4b3d-a5d7-b60e3ab14fec" />

Only showing one username because we only tried one for now to craft our detection.
### 2. Successful Login — `Initial Access - SSH Honeypot Login Success - T1110`

Any successful login to the honeypot is suspicious by definition — legitimate users don't SSH into a honeypot. This catches the attacker's credential and timestamps the breach.

```spl
index=main eventid="cowrie.login.success"
| table _time, src_ip, username, password
| sort _time
```
<img width="1396" height="886" alt="image" src="https://github.com/user-attachments/assets/ce842ae6-df74-42a0-b1da-dded73b9e207" />

The bruteforce for this username was quite fast and easy.
### 3. Attacker Command Harvest — `Execution - Honeypot Attacker Commands - T1059`

Every command typed inside the Cowrie shell is logged. This table gives you the full attacker playbook — what they ran, when, and from which session.

```spl
index=main eventid="cowrie.command.input"
| table _time, src_ip, session, input
| sort _time
```

<img width="1399" height="887" alt="image" src="https://github.com/user-attachments/assets/c45557a2-502e-444c-b084-dacba6098280" />

Now we can try to find how can have enrichment from each IP
### 4. IP Geolocation Enrichment — `Brute Force - Attacker Origin by Country - T1110`

Enriches the source IP with country and city using Splunk's built-in `iplocation` command. Shows where brute-force attempts are originating from — especially useful if the honeypot is internet-exposed and receiving real external traffic.

```spl
index=main eventid="cowrie.login.failed"
| stats count by src_ip
| iplocation src_ip
| table src_ip, count, Country, City
| sort -count
```

> **Note:** I personally used a randomized IP in my homelab simulating my attacker as a public Ip (evenb though it is internal). This is why the IP is showing united kingdom.

<img width="1395" height="885" alt="image" src="https://github.com/user-attachments/assets/9cb12200-0554-4b5d-b67a-9afbd85b7962" />

Now we will be creating dashboard so we detect whenever the attacker tries to brute force again.
---

## Dashboard — Cowrie Attacker Activity

Built a Splunk dashboard consolidating all honeypot telemetry into one view. To build it in the UI: **Dashboards → Create New Dashboard → Classic Dashboard** → add each panel using **Add Panel → New from Search**.

### Panel 1 — Brute Force Attempts Over Time
Visualization: **Line Chart**
```spl
index=main eventid="cowrie.login.failed"
| timechart count as "Failed Attempts" span=1m
```
<img width="1397" height="891" alt="image" src="https://github.com/user-attachments/assets/ab9fa879-cf41-4351-8d74-feb2a92e3efe" />

### Panel 2 — Top Attacking IPs (Geo-Enriched)
Visualization: **Table**
```spl
index=main eventid="cowrie.login.failed"
| stats count by src_ip
| iplocation src_ip
| table src_ip, count, Country, City
| sort -count
| head 10
```
<img width="1366" height="306" alt="image" src="https://github.com/user-attachments/assets/017c2ad1-d5a6-4bf2-9699-24bea2e1da23" />

### Panel 3 — Attacker Origin Map
Visualization: **Choropleth Map**
```spl
index=main eventid="cowrie.login.failed"
| stats count by src_ip
| iplocation src_ip
| geostats latfield=lat longfield=lon count
```
<img width="1368" height="654" alt="image" src="https://github.com/user-attachments/assets/21a00d0e-c1e5-46b5-b0d6-56b48a259799" />

### Panel 4 — Successful Logins
Visualization: **Table**
```spl
index=cowrie eventid="cowrie.login.success"
| table _time, src_ip, username, password
| sort _time
```
<img width="1372" height="312" alt="image" src="https://github.com/user-attachments/assets/9ef2bd9d-f11f-4139-99b6-327f890a60fb" />

### Panel 5 — Attacker Command Harvest
Visualization: **Table**
```spl
index=cowrie eventid="cowrie.command.input"
| table _time, src_ip, session, input
| sort _time
```
<img width="863" height="786" alt="image" src="https://github.com/user-attachments/assets/aa0f8943-43a3-4193-a298-c9e630d12f8f" />

<img width="1367" height="458" alt="image" src="https://github.com/user-attachments/assets/f595e698-7e1a-40da-bf3e-8407e573fc18" />

### SSH Login success alert.
Yes it is important to create dashboard to have better visibility of what you are dealing with, but I think it would be even better to also have an alert for a successful login so your analyst can look into what that attacker on the honeypot.
With that being said we will be using this search to add as an alert for that specific reason.

<img width="1390" height="878" alt="image" src="https://github.com/user-attachments/assets/5d9aa7f3-e229-4613-b3dd-f82f3854aa64" />

<img width="1156" height="747" alt="image" src="https://github.com/user-attachments/assets/b97cb6a8-961f-435f-b71f-eb10bce8b0de" />

## Detection Engineering Notes (Design Decisions)

- **Honeypot as a detection layer.** Every event in these logs is suspicious by definition — no legitimate user should be SSHing into this host. There is no noise to filter, no false positives to tune. Any hit is a real hit.
- **Credential harvest is automatic.** Cowrie logs the exact username and password used to log in. A successful login gives you the attacker's credential immediately — no forensics needed.
- **Command harvest survives tool changes.** The `cowrie.command.input` detection catches every command typed regardless of what tool the attacker uses or how they got in. The behavior (typing commands into a shell) is what's detected.
- **Real attacker data note.** If the honeypot is internet-exposed via pfSense port forwarding, the `cowrie.login.failed` query may return real brute-force attempts from external IPs — not just the simulated Kali attack. This is authentic threat intelligence and worth documenting separately.

---

## Results

| Detection | Technique | Source | Result |
|-----------|-----------|--------|--------|
| SSH Login Failures | T1110 | Cowrie `cowrie.login.failed` | ✅ Detected |
| SSH Honeypot Login Success | T1110 | Cowrie `cowrie.login.success` | ✅ Detected |
| Attacker Command Harvest | T1059 / T1082 | Cowrie `cowrie.command.input` | ✅ Detected |
| Attacker Origin by Country | T1110 | Cowrie + Splunk `iplocation` | ✅ Detected |

All stages captured in Cowrie JSON logs and detected in Splunk. Each saved as a real-time alert, re-validated by re-running the attack.
<img width="1916" height="959" alt="image" src="https://github.com/user-attachments/assets/17369309-025d-41ab-8815-ffe60d59d396" />

<img width="1913" height="967" alt="image" src="https://github.com/user-attachments/assets/c9f89bb7-0185-4bf3-a7e7-3a9eef4293b9" />

<img width="1909" height="228" alt="image" src="https://github.com/user-attachments/assets/b71d4a9f-fa36-4496-a015-d6cf7b78d44a" />

<img width="1912" height="718" alt="image" src="https://github.com/user-attachments/assets/cfa54e22-874a-434b-ac0f-f2d2451ca0ec" />

<img width="1741" height="1079" alt="image" src="https://github.com/user-attachments/assets/c5449d68-3514-4412-bfb5-453175fb55bd" />

<img width="1735" height="1040" alt="image" src="https://github.com/user-attachments/assets/3526e854-4f32-4a86-ac3e-727925f6a775" />

<img width="1742" height="1079" alt="image" src="https://github.com/user-attachments/assets/337661f8-c7e6-4727-91c4-c4ef6d43ad8a" />

<img width="1724" height="1079" alt="image" src="https://github.com/user-attachments/assets/840716f5-ab7a-47c8-940c-cf221e002aa9" />

---

## Key Takeaways

- Honeypots generate zero false positives — every event is real attacker activity by definition.
- Cowrie captures the full attacker playbook: credentials used, commands run, session timeline.
- This scenario produces authentic threat intelligence if the honeypot is internet-exposed — a real SOC would use this data to enrich threat feeds and block known attacker IPs.

---
Thanks for reading!
*Built in an isolated SOC homelab. Cowrie honeypot intentionally exposed to simulate attacker interaction.*
