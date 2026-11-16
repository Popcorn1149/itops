# IT Ops Workspace

**One console for the company's IT infrastructure** – map, monitoring, device logs, alerts, endpoints and security monitoring (ISO 27001 / ISO 9001 / SOC 2), configured entirely from the web UI.

| Version | Agent | Database | Runs on | Tests |
|---|---|---|---|---|
| **2.11.0** (2026-11-16) | 1.1.0 | PostgreSQL 17 | Windows (VS Code) · Linux (Docker) | 324 passed |

![System map](docs/map-tree.png)

**Contents**
[What it does](#what-it-does) ·
[Quick start](#quick-start) ·
[How do I…](#how-do-i) ·
[Guides](#guides) ·
[Reference](#reference) ·
[Testing](#testing) ·
[Troubleshooting](#troubleshooting) ·
[Roadmap](#roadmap) ·
[Changelog](#changelog) ·
[Other documents](#other-documents)

---

## What it does

| | |
|---|---|
| 🗺️ **Infrastructure** | System map (radial / tree / flow), sites, assets with auto-discovery, critical systems with dependencies and runbooks, automatic **risk points** (no backup, no monitoring, expiring SSL, full datastore, old snapshots…). |
| 📡 **Monitoring** | Ping, TCP, HTTP(S) + SSL expiry, SNMP v2c/v3, SSH (Linux, Docker, Hyper-V, Windows Event Log), VMware ESXi/vCenter, Proxmox, pfSense/OPNsense, Internet/WAN lines. |
| 🖥️ **Virtualization** | VMs and containers under each host with **used / allocated** CPU, RAM and disk. |
| 🧯 **CVEs** | Catalogue of new vulnerabilities from **NVD**, flagged when **exploited in the wild (CISA KEV)** and scored by **exploit probability (EPSS)**; synced daily. |
| 🐞 **Vulnerabilities** | Which CVE is on which machine, from **replaceable sources**: Wazuh (read-only), scanner file import, and IT Ops' own CPE matching for devices without an agent. Priority 0–100 and patch deadlines (SLA), overview, by machine, by CVE, Telegram alerts for KEV / P1, morning digest, CSV report. |
| 🌐 **Network traffic** | NetFlow / IPFIX from pfSense (softflowd) through **GoFlow2**: Internet up/down over time, top hosts, services, VLANs, destinations and conversations; local ↔ local traffic; alert when the firewall stops sending. |
| 📶 **Wi-Fi** | Aruba Instant APs: connected clients with name, IP, MAC, OS, ESSID, AP, **signal** and **link speed**. |
| 📜 **Device logs** | Syslog (514) and SNMP traps (162) linked to assets; **rules** turn logs into alerts and resolve them automatically. |
| 💻 **Endpoints** | Go agent for Windows / Linux / macOS: performance, Defender, services, software, security events, signed auto-update. |
| 🔔 **Alerts & automation** | SLA, grouping by root cause, flapping protection, runbooks; Telegram / email / webhook; digests, SLA reports, maintenance windows. |
| 🛡️ **Security** | Admin-action alerts, silent-source detection, hash-chained log archive · tool itself: mandatory admin 2FA, AES-256-GCM secrets, append-only audit log, daily backup. |

> The UI and all generated messages are in **English**. A Vietnamese translation exists but the switch is hidden (`SHOW_LANG_SWITCH` in `frontend/src/App.jsx`). Raw device logs, hostnames and data you type are shown as-is; records created before 2.3.0 keep their original wording.

---

## Quick start

**Windows + VS Code (≈ 10 minutes)**

1. Install **Python** (tick *Add python.exe to PATH*) and **VS Code**.
2. Unzip, double-click **`SETUP.bat`** – installs everything and prints the **admin account** (keep it).
3. Run **`OPEN-FIREWALL.bat`** as Administrator – opens ports 8100 / 514 / 162 to the LAN.
4. VS Code → `Ctrl+Shift+D` → choose a configuration → `F5` → open `http://127.0.0.1:8100`.
5. Sign in and enable **2FA** (Google / Microsoft Authenticator) – required for admins.

| Launch configuration | Use it for |
|---|---|
| ▶ Chạy IT Ops (dữ liệu mẫu) | **Demo** – realistic sample logs and alerts, no devices needed |
| ▶ Thiết bị thật (cổng 514/162) | **Production** on this machine |
| ▶ Song song với v1 … | **Trial next to v1** – no log listeners, no notifications |
| ▶ Chạy IT Ops (HTTPS, dữ liệu mẫu) | HTTPS on 8443 (run task 8 first) |

*Launch configuration and task names are still in Vietnamese.*

**Upgrade:** copy the new code over the folder (keep `backend/data-*`) → `Shift+F5` → `F5`. The database upgrades itself.

---

## How do I…

| I want to… | Go to |
|---|---|
| Add a firewall, switch, host or AP | [Add devices](#add-devices) |
| Receive logs from devices | [Syslog and SNMP traps](#syslog-and-snmp-traps) |
| See who is connected to a Wi-Fi AP | [Aruba Wi-Fi clients](#aruba-wi-fi-clients) |
| Monitor PCs and servers from inside | [Endpoint agent](#endpoint-agent) |
| Move IT Ops to a new machine (keep data, keys, device settings) | [MIGRATE-TO-NEW-MACHINE.md](MIGRATE-TO-NEW-MACHINE.md) |
| See who uses the Internet line, for what | [Network traffic](#network-traffic) |
| Bring over data from v1 | [Move from v1](#move-from-v1) |
| Back up or restore | [Backup and restore](#backup-and-restore) |
| Run on a Linux server | [Linux server (Docker)](#linux-server-docker) |
| Follow new vulnerabilities | [CVE feeds](#cve-feeds) |
| Fix "No SNMP response" and similar | [Troubleshooting](#troubleshooting) |

---

## Guides

### Add devices
Recommended order – each step builds on the previous one:

1. **Sites** – head office, branches, VPS.
2. **Firewalls** – asset type *Firewall* + a *pfSense / OPNsense* check.
3. **Switches** – *behind* the firewall + an *SNMP* check.
4. **Hosts** – *behind* a switch + an *ESXi / Proxmox / SSH (Hyper-V)* check → VMs appear automatically.
5. **Critical systems** – AD, ERP, file server, email… linked to their VMs.
6. **Backups** – mark each system as backed up until *Not backed up* reaches 0.

Device-side preparation (pfSense REST API, ESXi read-only user, Proxmox token, SNMP, SSH, Telegram bot): **[ADD-REAL-DEVICES.md](ADD-REAL-DEVICES.md)**.

### Syslog and SNMP traps
- Point devices to `<IT Ops IP>:514` (syslog) and `:162` (traps).
- Only private ranges are accepted by default – change under *Settings → Syslog/Trap receivers*.
- *Device Logs → Device configuration guide* has ready-made commands per vendor; *Unknown sources* shows blocked senders.
- Test without devices: `backend/tools/simulate_devices.py` (or task 10) sends real syslog/trap packets.

### Aruba Wi-Fi clients
1. On each AP (a standalone Instant AP is its own virtual controller): `https://<AP>:4343` → *System → Show advanced settings → Monitoring*, or CLI `snmp-server community <string>` then `commit apply`.
2. Allow **UDP 161** from the IT Ops machine to the APs.
3. Add an **SNMP** check on the AP → *Run now* → the client list appears under **Collected data** (refreshed every run).

| Signal (SNR) | Meaning |
|---|---|
| ≥ 40 dB Excellent · 25–39 Good | Normal |
| 20–24 Fair | Slower, occasional drops |
| < 20 Poor | Drops, retries – device too far / blocked |

Speed is the link rate negotiated with the AP (device→AP / AP→device), not actual throughput.
Diagnose: `backend\.venv\Scripts\python.exe backend\tools\snmp_test.py <ip> <community>`.
`show running-config` shows the community **encrypted** – use the plain string.

### Endpoint agent
1. *Endpoints → Install agent* — copy the command (enrollment is open, like Wazuh: no token; optionally pick a site).
2. On the endpoint, PowerShell **as Administrator**:
   ```
   .\itops-agent-windows-amd64.exe install --server http://<IT Ops IP>:8100 --allow-http [--site "HCMC"]
   & "C:\Program Files\ITOpsAgent\itops-agent.exe" status
   ```
3. The machine appears under *Endpoints* within ~1 minute.

**Reinstalling on a machine that is already listed** (new agent, same hostname + machine ID/serial – e.g. after reinstalling Windows)
needs **IT approval**: the request shows up under *Endpoints → Pending approvals* with the current and the new details side by side
(source IP, MAC, serial, machine ID…). The current agent keeps working until you approve; the new agent asks again every 5 minutes and
starts on its own once approved. Re-running the installer on the *same* installation (e.g. GPO at every boot) needs no approval.

**Update:** `net stop ITOpsAgent` → copy the new `itops-agent-windows-amd64.exe` over `C:\Program Files\ITOpsAgent\itops-agent.exe` → `net start ITOpsAgent`.
**Production:** use HTTPS + `--ca-pin`; GPO roll-out and auto-update in **[agent/README.md](agent/README.md)**.

### Network traffic
*Operations → Network traffic* shows Internet download / upload over time, top hosts, services (port), interfaces / VLANs,
Internet destinations and the largest conversations – 1 hour to 30 days. Click a host or an interface to filter.

**How it works:** pfSense (package **softflowd**) sends flow records → **GoFlow2** (NetFlow v5/v9, IPFIX, sFlow collector,
BSD licence, started and stopped by IT Ops) → IT Ops sums them per minute in PostgreSQL. Only traffic with a local address
is kept, so copies seen on WAN / PPPoE after NAT are ignored, and local ↔ local traffic routed between two VLANs is counted once.

1. **GoFlow2:** copy `goflow2-2.2.7-windows-amd64.exe` into `backend\tools\goflow2\` (checksums in the README there).
   Docker: already in the image. Linux without Docker: `goflow2` on the PATH, or `FLOW_COLLECTOR=<path>`.
2. **Firewall:** run `OPEN-FIREWALL.bat` again (opens UDP 2055 / 6343 and removes the "block goflow2" rule Windows may have added).
3. **IT Ops:** *Network traffic → Settings* → tick **Collect traffic**, check **Local networks**, Save. The collector box shows *running*.
4. **pfSense:** *System → Package Manager* → install **softflowd**; *Services → softflowd*:
   - Interfaces: the **LAN / VLAN** interfaces only – **not** WAN / PPPoE (traffic after NAT, counted twice) and not the trunk parent (`em0`).
   - Host: the IT Ops machine · Port: **2055** (the package default is 9996) · Version: **IPFIX** · Flow tracking level: **Full**.
   - Timeouts (general / TCP / UDP / ICMP) **60**, Maximum lifetime **120** – otherwise long connections appear up to an hour late.
5. **Interface names:** softflowd numbers interfaces itself (`-i 15:em0.15`), not with the SNMP ifIndex. The box appears in
   *Settings* once the first flow records have arrived. First pick the **Firewall asset** (pfSense often sends from a VLAN
   address that differs from the asset's IP), then paste the output of `ps aux | grep softflowd` (*Diagnostics → Command Prompt*) –
   IT Ops reads the numbers and adds the VLAN descriptions from the pfSense / SNMP check of that firewall.

| Good to know | |
|---|---|
| Storage | 1-minute detail kept **7 days**, hourly totals (without the remote IP) **60 days** (editable). Roughly 250–300 MB per working day for ~250 flow records/s. Not in the daily backup. |
| Load on pfSense | softflowd copies packets to user space: on a 2-core firewall turn interfaces on a few at a time and watch the firewall's CPU in IT Ops. |
| Alerts | *No traffic data from <firewall>* after 15 minutes of silence (editable); *Traffic collector (GoFlow2) is not running* after 5 minutes. Both close by themselves. |
| Limits | Addresses and ports only – no web addresses (HTTPS). Names come from assets and endpoint agents; Internet destinations are IPs for now. softflowd records ICMP as protocol 0 (softflowd bug). |
| Diagnose | *Settings* shows the collector command, its last log lines, records/s and the share of records ignored (no local address). |

### Move from v1
Keep v1 in `Documents\itops`, v2 in `Documents\itops-v2`.

1. Stop v2, double-click **`MIGRATE-V1-DATA.bat`** (task 19), type `YES` – takes a safe snapshot of the **running** v1 database and its key; v1 files are only read.
2. Start **▶ Song song với v1**, sign in with the **old** admin password, enable 2FA.
3. Daily: task **20** – v1 ↔ v2 comparison report (`backend\data-v2-local\reports\`).
4. Switch over: stop v1 → run step 1 once more → start **▶ Thiết bị thật**.

### CVE feeds
*Operations → CVEs* lists recently published CVEs with severity (CVSS), **KEV** (exploited in the wild) and **EPSS** (probability of exploitation in 30 days). Prioritise KEV first, then high EPSS, then CVSS.

- Synced automatically ~90 s after start and then every 24 h; admins can press **Sync now**.
- First sync loads CVEs modified in the last 120 days plus every KEV entry (a few minutes without an API key).
- Needs outbound HTTPS to `services.nvd.nist.gov`, `www.cisa.gov` (fallback: CISA's copy on `raw.githubusercontent.com`) and `epss.empiricalsecurity.com` (fallback `epss.cyentia.com`).
- Optional free NVD API key (`NVD_API_KEY`) makes syncing ~10× faster. Other settings: `CVE_SYNC=0`, `CVE_SYNC_HOURS`, `CVE_BACKFILL_DAYS`, `NVD_URL` / `KEV_URL` / `EPSS_URL` (mirrors).
- Feed status is shown on the page; one failing feed does not stop the others.
- Which of **your** machines are affected: see [Vulnerabilities and Wazuh](#vulnerabilities-and-wazuh).

### Vulnerabilities and Wazuh
*Operations → Vulnerabilities* shows **which CVE is on which machine**. IT Ops is the core; the tools that find vulnerabilities are **sources** that can be added, compared, switched off or replaced.

| Source | What it covers | Confidence (default) |
|---|---|---|
| **Wazuh** (read-only) | machines with a Wazuh agent – exact package / version match | high |
| **File import** (CSV / JSON) | any scanner export, or a Wazuh Discover CSV; also the fallback while a tool is down | medium |
| **IT Ops CPE matching** (built in) | devices without an agent – ESXi, vCenter, FortiGate, pfSense, OPNsense, Proxmox, ArubaOS, RouterOS, Synology – from the version they report | medium |

**Connect Wazuh** (tested with 4.14)
1. In Wazuh create two **read-only** users: one for the **server API** (port 55000, read agents + syscollector) and one for the **indexer** (port 9200, `read` on `wazuh-states-vulnerabilities-*`). Do not use `admin` long-term.
2. From the IT Ops machine check the ports: `Test-NetConnection <wazuh-ip> -Port 55000` and `-Port 9200` → `TcpTestSucceeded : True`.
3. *Vulnerabilities → Add Wazuh*: URLs, users, passwords (stored encrypted), and paste Wazuh's **root CA** (`/etc/wazuh-indexer/certs/root-ca.pem`). Keep *Verify TLS* on; use the same host name / IP the certificate was issued for.
4. **Test** → shows the Wazuh version, number of agents and vulnerability records. Then **Sync now** (afterwards every 6 h).
5. **Unmatched hosts**: Wazuh agents IT Ops could not link safely to a machine (no unique serial, name or IP). IT Ops never guesses – map them by hand or ignore them.

**How results are handled**
- One finding = one CVE on one machine, whoever reports it. Changing tools keeps *first seen*, triage and history.
- **Severity, KEV and EPSS always come from the IT Ops CVE catalogue.** A source's own score is shown for reference only (and temporarily, marked `*`, while NVD has not been synced for that CVE – such CVEs are queued for the next NVD sync).
- **Confidence** says how sure a result is, not how dangerous it is. Medium / low results seen by one source only are flagged **verify** until a person confirms them or a second source sees them.
- A finding becomes **fixed** only when an enabled source scans the machine again and no longer lists it. Machines a source did not scan (agent disconnected) keep their findings.
- Disabling a source never closes its findings: those seen only by it become **source off** (unknown, not fixed).
- A source that has not synced successfully for 3× its interval (minimum 24 h; file imports: 30 days) is marked **stale**, and so are its findings.
- **False positive** (reason) and **accepted risk** (reason + review date) are kept per machine + CVE and written to the audit log.
- **Compare sources** shows, on machines both cover, what both see and what only one sees – use it during a parallel run before switching tools.
- Identify a device precisely for CPE matching: asset → *meta* → `"cpe": "vendor:product:version"` (several separated by `;`).
- `VULN_SYNC=0` turns off scheduled source syncs (manual *Sync now* / imports still work).

**Priority and patch deadlines** (*Policy* tab)
- Priority 0–100 = CVSS × 6 + 25 if exploited (KEV) + 5 if ransomware + EPSS percentile × 10 + machine importance (*Critical systems*: High + 10, Medium + 5, Low − 5). **P1** ≥ 80 · **P2** ≥ 60 · **P3** ≥ 40 · **P4** below. Only the IT Ops catalogue and your own data are used.
- Deadline = confirmation time + days for the class: **KEV 1 · Critical 7 · High 30 · Medium 90 · Low 180 · not scored 30** (editable). The clock starts when the finding is confirmed (high confidence, two sources, or *Mark verified*); unconfirmed findings show *Not started*.
- A finding that comes back after being fixed gets a new deadline. False positives and accepted risk (until the review date) have no deadline. If CISA adds a CVE to KEV later, its deadline tightens automatically.
- Priorities and deadlines are recalculated after every source sync, every CVE sync, every policy change and every hour.

**Screens, alerts, reports**
- *Overview*: open, overdue, due soon, KEV, awaiting verification, fixed in 30 days (% on time), open by priority, 30-day new vs fixed, machines and CVEs needing attention. Every number opens the matching list.
- *By machine* / *By CVE*: grouped views; *CVEs* page drawer shows **Our machines** for that CVE.
- **Alerts** (Settings › Notifications channels): one message per sync for new confirmed findings that are KEV or priority ≥ 80 (editable) – each finding only once.
- **Morning digest** (default 08:00 local): overdue, due soon, new / fixed in 24 h, KEV open, top 10 overdue. Sent only when there is something to report; *Send digest now* on the Policy tab.
- **Export CSV** on the Findings tab (opens in Excel, UTF-8).

**Try it with demo data** – *▶ Chạy IT Ops (dữ liệu mẫu)* adds a **simulated Wazuh** (5 agents: PC-KD03, PC-LA, SRV-FILE01, srv-web01 and WAZUH-LAB-07, which is deliberately unmatched) with P1–P3 findings, KEV, overdue and already-fixed examples. It exists only in the demo database, never in real data; alerts for these samples are muted.

**Before upgrading Wazuh** (checklist)
1. Read the Wazuh release notes for changes to the vulnerability index or API.
2. After the upgrade press **Test**, then **Sync now**. If Wazuh changed its data format the sync stops with *unexpected format* and the previous results are kept.
3. If the version shown is not the tested one (⚠ on the source card), compare a few machines with the Wazuh dashboard before relying on the results.

### Remediation Mapping (how to fix a finding)
Open a finding → tab **Remediation**: what to do – **Fix** first, then *Reduce risk now* and short *Reminders* – built from **official, structured data only**; every fact shows its source.

| Data | From | Gives |
|---|---|---|
| Vendor advisory API | **Microsoft MSRC** (CVRF API, no key) – daily for open Microsoft findings + on demand | KB number per Windows edition, fixed build, restart, workarounds, exploit status |
| **Official CVE record** (CNA, CVE Program *cvelistV5* on GitHub, no key) – for CVEs NVD has not analysed or that are not in the catalogue | affected / fixed versions written by the issuer, advisory links, CNA CVSS, CISA exploitation assessment |
| The scanner that found it | e.g. **Wazuh** `fixed_version` (from distro advisories) | package + fixed version (Linux) |
| CVE catalogue | NVD / CNA **version ranges**, **CISA KEV** required action | "update X from 12.1.2 to ≥ 12.2.0.334", mitigation |
| IT Ops (fixed set, not a rule matrix) | backup, change request, check for compromise when exploited, verify, evidence | standard steps |

- The machine's own data is used: only the KB for *its* Windows edition is shown, and its build is compared with the fixed build (*not patched yet* / *already patched*).
- **Nothing is claimed that the sources do not say.** Each finding shows *Affected* (is the installed version inside the affected versions?), *Not known* (e.g. "fixed version – not published in NVD, the CVE record") and *Exposure* (server / endpoint, how many other machines have it). Without a published fix there is **no "update" step** – *Next* says what to check (vendor release notes for a version newer than X that mentions the CVE) and that IT Ops re-checks the sources daily. Installed version outside the affected range → *Check installed version* (possible scanner false positive). Scanner and agent inventory see different versions → *Versions differ* (two copies installed?). *Watch*: Defender detections on the machine alert automatically.
- Other pages are **links only** (vendor advisory, CISA, NVD, CVE.org, Wazuh CTI); exploit / PoC links are hidden. Nothing is scraped and IT Ops never runs anything on the machine.
- **Copy as text** → paste into the change request / ticket.
- The tab opens at once; a missing Microsoft record is fetched in the background and appears by itself a few seconds later. One monthly Microsoft document (several MB) is read in memory and dropped – only the few KB per CVE are saved, other open CVEs from the same document are saved in the same pass, and records of CVEs with no finding are removed at the daily sync.
- MSRC unreachable → the last saved copy is used; the playbook still shows CVE-catalogue data. `REMEDIATION_MSRC=0` turns the lookup off; `MSRC_URL` points to a mirror.

### Backup and restore
- **Automatic** every day: database + both keys + archive → `backend/data-*/backups`.
- **Manual:** task 7. **Restore:** stop the app → task 13 → start again.
- Without `.enc_key` stored device passwords cannot be decrypted – keep backups off the machine.

### Linux server (Docker)
```bash
cp .env.example .env    # set ADMIN_PASSWORD, POSTGRES_PASSWORD, DEMO_DATA=false
docker compose up -d --build
docker compose exec itops python -m app.admin_tools restore /data/<backup>.zip --wipe   # bring data over
```
*Not yet verified on a real VM.*

---

## Reference

**Ports and folders**

| | Real devices | Sample data |
|---|---|---|
| Web | 8100 · HTTPS 8443 | 8100 |
| Syslog / traps | 514 / 162 | 6514 / 6162 (127.0.0.1 only) |
| NetFlow / IPFIX · sFlow (when enabled) | UDP 2055 · 6343 | same |
| Data folder | `backend/data-v2-local` | `backend/data-v2-dev` |
| PostgreSQL (127.0.0.1) | 5434 | 5433 |

Own PostgreSQL server: `DATABASE_URL=postgresql+psycopg://user:pass@host:5432/itops`.

**Environment flags**

| Flag | Effect |
|---|---|
| `DISABLE_RECEIVERS=1` | Do not listen on 514 / 162 |
| `DISABLE_NOTIFY=1` | No Telegram / email / webhook (test sends still work) |
| `DISABLE_FLOW=1` | Never start the traffic collector (set in *Song song với v1*) |
| `FLOW_COLLECTOR` | Full path of the GoFlow2 program (default: `backend/tools/goflow2/`, then the PATH) |
| `DISABLE_SCHEDULER=1` | Do not run checks |
| `REQUIRE_2FA_ADMIN` | Default `1` |
| `SESSION_IDLE_MINUTES` | Idle sign-out, default 30 |
| `ALLOW_SSH_COMMAND=1` | Allow custom SSH commands (locked by default) |
| `ITOPS_ENV=production` | Lock *reset data* |
| `CVE_SYNC=0` · `CVE_SYNC_HOURS` · `CVE_BACKFILL_DAYS` · `NVD_API_KEY` | CVE feed sync (see [CVE feeds](#cve-feeds)) |
| `DEMO_DATA` · `DEMO_LOGS` · `DEMO_AGENTS` · `DEMO_INCIDENT_EVERY` | Sample data controls |

**VS Code tasks** (Terminal → Run Task)

| # | Task | # | Task |
|---|---|---|---|
| 0–1 | Install (PostgreSQL, Python) | 11–12 | Stop PostgreSQL |
| 2–3 | Build the UI (Node.js) | 13 | Restore a backup |
| 4 | Send a test syslog | 14 | Import a stopped v1 database |
| 5 | Run tests | 15–16 | Reset a forgotten admin password |
| 6 | Wipe sample data | 17 | Agent simulator (Windows + macOS) |
| 7 | Backup now | 18 | Verify source files |
| 8 | Create HTTPS certificate | 19 | Import the **running** v1 database |
| 9 | Reset admin 2FA | 20 | v1 ↔ v2 comparison report |
| 10 | Device simulator (real packets) | | |

---

## Testing

```
cd backend
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider --ignore=tests/test_real_agents.py --ignore=tests/load_test.py
```
- Tests create a temporary PostgreSQL database – sample and real data are never touched (task 5 does the same).
- Existing server: `TEST_DATABASE_URL=postgresql://user:pass@host:5432/postgres` (needs CREATEDB).
- Agent: `cd agent && go test ./... && ./scripts/build.sh <version>` (Go ≥ 1.24, offline).
- History: [QA_REPORT.md](QA_REPORT.md).

---

## Troubleshooting

| Symptom | Likely cause → fix |
|---|---|
| Ping "not responding", device is up | ICMP blocked between IT Ops and the device |
| SNMP "No SNMP response … timeout" | Wrong community (silently ignored) · wrong version · UDP 161 blocked · SNMP off → run `tools/snmp_test.py` |
| pfSense 404 / 401 | REST API package missing / wrong key or key auth disabled |
| ESXi VMs without CPU/RAM | ESXi SNMP has no per-VM usage → add a read-only ESXi user to the check |
| Endpoint shows only its hostname | Windows agent < 1.0.1 → update the agent |
| "Try again later" at sign-in | 5 failed attempts → wait 5 minutes |
| Lost the admin's 2FA phone | Stop the app → task 9 → start again |
| UI looks outdated after an update | `Ctrl+F5` in the browser |

---

## Roadmap

Work proceeds in small releases; each finished part becomes a changelog entry.

**CVE module** (design: *IT Ops – CVE module design* document)

| Part | Scope | Status |
|---|---|---|
| 1. Asset data | OS build/UBR, users, machine identity, normalized software, data quality | ✅ 2.2.0 |
| 2. CVE catalogue & feeds | `cves` table; daily NVD, CISA KEV, EPSS sync; *Operations → CVEs* page | ✅ 2.5.0 |
| 3. Matching | findings per machine from replaceable sources: Wazuh (read-only), file import, IT Ops CPE matching; *Operations → Vulnerabilities* | ✅ 2.6.0 |
| 4. Priority, SLA, status | score 0–100 from the catalogue + asset importance, patch deadlines per (machine, CVE) | ✅ 2.7.0 |
| 5. Screens, alerts, reports | Overview, By machine, By CVE, CVE detail; alerts for KEV / P1; morning digest; CSV | ✅ 2.7.0 |

**Decision A – taken 2026-11-10: IT Ops core + replaceable sources**

Principle: *usable now, extensible, flexible, not over-dependent – a core that IT Ops owns, with parts that can be replaced.*
No external tool may be at the same time the only data source, the only storage and the only place where logic runs.

| Core (owned by IT Ops, no external dependency) | Replaceable (adapters in `backend/app/vulnsrc/`) |
|---|---|
| machine inventory (agent, SNMP), PostgreSQL + history, CVE catalogue (NVD / KEV / EPSS), findings, triage, priority / SLA, UI, alerts | Wazuh (endpoint scanning), file import, IT Ops CPE matching; later any other scanner |

Rules (enforced by tests in `tests/test_cve_p3.py`):
1. Priority is computed by IT Ops from the catalogue and asset importance – a source's score is reference only.
2. Findings are keyed by (machine, CVE) – changing tools does not reset first seen, SLA or triage.
3. Disabling a source never marks findings fixed (*source off*).
4. Confidence is a gate (*verify*), never a weight; it is set once per source and tuned during a parallel run.
5. Switch tools with a parallel run + *Compare sources* before disabling the old one.
6. Keep it small: two adapters to start (Wazuh, file import) plus the built-in CPE matching; add more only on real need.

Acceptance tests (pass in 2.6.0): Wazuh unreachable → core keeps working, results marked stale, nothing "fixed"; priority does not depend on Wazuh's CVE data; Wazuh replaced by a file import → same findings, first seen and triage.

Risks to watch:

| Risk | Control |
|---|---|
| Wazuh stops development, is sold, or its feed stops | core independent; stale labels; file import + CPE matching as fallback; replace the adapter |
| Wazuh upgrade changes its data format | adapter checks the format and stops without losing data; tested-version flag; upgrade checklist above |
| Wazuh agent linked to the wrong machine | serial → name → IP, unique only; otherwise *unmatched* for manual mapping |
| NVD late in scoring new CVEs | source score shown temporarily (marked `*`); missing CVEs queued for NVD |
| IT Ops becomes a map of every weakness | read-only Wazuh users, TLS verification with Wazuh CA, viewers cannot change anything, audit log |
| Loss of the IT Ops database (now holds history and triage) | daily backup (*Backup and restore*); test a restore at least once |
| One person maintains it | this README, small isolated adapters, tests for every rule |

**Decision B – taken 2026-11-11: default patch deadlines** KEV 1 day · Critical 7 · High 30 · Medium 90 · Low 180 · not scored 30 days, counted from confirmation; editable in *Vulnerabilities › Policy* (changes are audited).

**Agent – to do** (noted 2026-11-11)

| Item | Scope | Status |
|---|---|---|
| Update signing key | **Once**, on the admin's machine (never on the server): `itops-agent-release.exe keygen --out <USB>` → keep `update-signing.key` offline, note the public key | ⏳ to do (IT) |
| Public key on agents | add `--update-pubkey <public key>` to the install command / GPO script; existing machines (e.g. COMPUTER-0000) need one manual update with the key | ⏳ to do (IT), after the key exists |
| Update from Endpoints | IT uploads a signed release, selects machines / site / tag on Endpoints → *Update to X.Y.Z*; agent picks it up within ~1 min, verifies the signature, shows *pending → updating → done / failed* | planned, needs the two items above |
| Near real-time events | agent listens to Event Log and sends alert-worthy events within seconds; performance stays at 30–60 s | proposed – waiting for decision |

Until the key exists, update agents by hand: `net stop ITOpsAgent` → copy the new `itops-agent-windows-amd64.exe` over
`C:\Program Files\ITOpsAgent\itops-agent.exe` → `net start ITOpsAgent` (keeps the key, no approval needed).

**Wazuh – later, only if needed** (cloud modules excluded)
- Link-out buttons from each machine to the Wazuh dashboard (SCA, FIM, malware, MITRE) – low effort, no maintenance.
- Deeper integration of SCA / FIM / malware / MITRE, and TSC (SOC 2) evidence reports when an audit is scheduled.

---

## Changelog

Newest first. Agent versions are independent (`backend/agent_dist/VERSION`); database migrations run automatically at startup.

> **Maintaining this changelog** – every change that reaches machine 1 gets an entry here. For a release:
> bump `VERSION` in `backend/app/main.py` (and `frontend/package.json`), update the header table, add
> `### <version> · <YYYY-MM-DD> · <theme>` with **Added / Changed / Fixed** lines, and note migrations and agent versions.
> `backend/tests/test_readme_changelog.py` fails if the README does not match the running version.

### 2.11.0 · 2026-11-16 · Open agent enrollment (Wazuh-style) · machine migration · English file names
- **Changed** agent enrollment is **open**, like Wazuh: the install command only needs the server address — registration tokens are gone (UI, API `/api/agent-tokens`, `agent_enroll_tokens` table; migration `0015`). Each machine still gets its own key; a machine matching an existing one still waits for IT approval under *Pending approvals*; new machines per source IP are rate-limited (`AGENT_ENROLL_NEW_PER_IP`, default 60/10 min).
- **Added** agent **1.1.0**: `install` without `--token`, new `--site "<name>"` / `--tags a,b` (assign on enroll) and `--re-enroll` (re-register after the server moved; keeps the old key if the server refuses). Install scripts: `install-windows.ps1 -Site/-Tags`, `install-linux.sh` / `install-macos.sh` take `[CA_PIN] [SITE]`. `simulate` no longer needs a token.
- **Changed** *Endpoints → Install agent* now shows ready-to-copy commands (with an optional site picker) instead of the token table.
- **Added** two-step move to a new machine: `PREPARE-MIGRATION.bat` on the old machine (backup → stop PostgreSQL → new `MANIFEST.sha256` → one zip on the Desktop) and `SETUP-NEW-MACHINE.bat` on the new one (installs Python / VS Code if missing → `SETUP.bat` → restore → firewall → VS Code). See `MIGRATE-TO-NEW-MACHINE.md`.
- **Changed** `SETUP.bat` recreates a `.venv` copied from another machine and has an `/auto` mode (no key presses).
- **Changed** every script and document file name is now English, and script messages are English: `CAI-DAT.bat` → `SETUP.bat`, `MO-TUONG-LUA.bat` → `OPEN-FIREWALL.bat`, `CHUYEN-DU-LIEU-V1.bat` → `MIGRATE-V1-DATA.bat`, `CHUYEN-MAY-MOI.md` → `MIGRATE-TO-NEW-MACHINE.md`, `CHAY-THU-VSCODE.md` → `RUN-IN-VSCODE.md`, `GIAM-SAT-AN-NINH.md` → `SECURITY-MONITORING.md`, `THEM-THIET-BI-THAT.md` → `ADD-REAL-DEVICES.md`, `TU-DONG-HOA.md` → `AUTOMATION.md`; tools `kiem_tra_file.py` → `verify_files.py`, `chuyen_v1.py` → `migrate_v1.py`, `mo_phong_thiet_bi.py` → `simulate_devices.py` (`--phuc-hoi` → `--recovery`, old flag still accepted), `so_sanh_v1_v2.py` → `compare_v1_v2.py`; `DECISIONS/0002-security-p1.md`, `DECISIONS/0004-go-agent-and-event-log.md`. VS Code task and launch names are unchanged.
- **Added** `_backup/` for copies of replaced files (see `_backup/README.md`); not packed, not in Git.

### 2.10.0 · 2026-11-13 · Network traffic (NetFlow / IPFIX)
- **Added** *Operations → Network traffic*: Internet download / upload chart, peak, top hosts (names from assets and endpoint agents), services by port, interfaces / VLANs, Internet destinations, largest conversations and local ↔ local traffic; 1 h – 30 days; click to filter by host or interface.
- **Added** traffic collector: IT Ops starts **GoFlow2** (NetFlow v5/v9, IPFIX, optional sFlow) as a child process, restarts it with back-off, reads its JSON output (also when two workers write on one line), keeps only traffic with a local address and counts routed local ↔ local traffic once. Settings (admin, audited): on/off, ports, local networks, silence threshold, retention.
- **Added** tables `flow_1m` (1-minute detail, 7 days), `flow_1h` (hourly, 60 days), `flow_exporters` – migration **0014**. Traffic tables are not part of the daily backup.
- **Added** interface names per exporter, including *paste `ps aux | grep softflowd`* with VLAN descriptions taken from the pfSense / SNMP check (softflowd does not use the SNMP ifIndex).
- **Added** alerts *No traffic data from <firewall>* and *Traffic collector (GoFlow2) is not running* (auto-resolve).
- **Changed** `OPEN-FIREWALL.bat` opens UDP 2055 / 6343 and removes a Windows "block goflow2" rule; *Song song với v1* sets `DISABLE_FLOW=1`; Docker image includes GoFlow2 2.2.7 (checksum-pinned).
- **Added** *Firewall asset* per exporter in *Network traffic → Settings*: pfSense sends flows from a VLAN address (e.g. 172.17.15.1) while the asset is registered with another (172.17.11.1) – link it once so the exporter gets the firewall's name and the VLAN descriptions of its pfSense / SNMP check.
- **Added** a GoFlow2 left running by an abrupt stop (VS Code *Shift+F5*) is stopped at the next start (PID file `DATA_DIR/goflow2.pid`, only if that PID is really GoFlow2), so UDP 2055 is free again.
- **Changed** *Settings* explains where the interface-name box appears (after the first flow records) and shows the records received so far; GoFlow2's normal start-up warning *template error* (WARN) is no longer shown as the collector's error.
- **Added** `MIGRATE-TO-NEW-MACHINE.md`: checklist for moving IT Ops to a new machine (backup → copy git-ignored files → install → restore → repoint devices → verify).
- **Fixed** two error messages still in Vietnamese in the UI: *Cannot reach the IT Ops server…* (server stopped / network lost) and *Error <status>*.
- Found during the trial on the real network (2026-11-13): softflowd's default port is 9996, it numbers interfaces itself, WAN export doubles the data, ICMP arrives as protocol 0 and pfSense sends from its VLAN address – all handled or documented above. First live run on FW-Core: ~530 records/s, 280 hosts in 6 minutes, pfSense CPU 20 % with softflowd on all interfaces.

### 2.9.0 · 2026-11-11 · Remediation Mapping
- **Added** *Remediation* tab on every finding: what to do (Fix → Reduce risk now → Reminders, no checkboxes) mapped from structured vendor data – Microsoft MSRC KB / fixed build per Windows edition, the scanner's fixed version, NVD/CNA version ranges and CISA KEV required action – with the source on every step, reference links (exploit links hidden) and *Copy as text* for the change request.
- **Added** advisory cache (table `advisories`, migration **0011**) refreshed with the daily CVE sync (feed `msrc`), in the background when a finding is opened, and on demand (*Refresh*, admin); a failed refresh keeps the last good copy; unused records are pruned.
- **Fixed** the daily `msrc` feed query (PostgreSQL cannot DISTINCT JSON columns).
- **Changed** Remediation when no fix is published: no more "update to the latest version" claim; instead *Affected / Not known / Exposure* facts, *Next* checks and *Watch*; out-of-range versions flagged as possible false positives; differing versions (scanner vs agent) reported.
- **Fixed** findings whose CVE is not in the catalogue (reported by Wazuh but older than the 120-day NVD window) or that NVD has not analysed showed *no fix*: IT Ops now reads the **official CVE record** (cvelistV5) – in the background when a finding is opened and daily (feed `cverecord`) – adds the CVE to the catalogue from it and maps the CNA's affected versions (text `<= 26.00`, `lessThan`/`lessThanOrEqual`, Log4j-style `changes`, CNA naming slips) to the installed package. Example: CVE-2026-48095 → *Update 7-Zip 26.00 (x64) to a version newer than 26.00*. Package matching uses whole words ("zip" no longer matches WinZip). Missing CVEs fetched from NVD per sync raised 100 → 300 (`NVD_WANTED_PER_SYNC`). "No fix" text no longer points to links that do not exist.
- **Changed** endpoint list: *User*, *IP* and *MAC* are separate columns; fixed the *All operating systems* filter label.
- **Added** `docs/BACKLOG.md` – features discussed but postponed (NVD coverage indicator, stale-feed alert, CNA/EUVD sources, Linux/OSV advisories, rule matrix, agent update button…).

### 2.8.0 · 2026-11-11 · Re-enrolment approval, MAC addresses, 2FA time limit
- **Added** IT approval for re-enrolment over an existing endpoint: a new agent that matches a listed machine (same hostname + machine ID or serial) no longer takes over its record. It gets *Pending approvals* on the Endpoints page (current vs new details, differences highlighted), an alert and an audit entry; the current agent keeps its key until IT approves. Reject = the new agent stops; approve = it picks up its key within ~5 minutes. Requests expire after 7 days. Migration **0010**.
- **Added** MAC addresses of active network cards: agent **1.0.4** reports them; shown in the endpoint list (*User · IP · MAC*), details and approval screen, and searchable. Older agents keep working (MAC shows “not reported”).
- **Added** 2FA step time limit: after a correct password the code must be entered within **3 minutes** (`MFA_STEP_SECONDS`), enforced by the server with a one-time ticket bound to the IP; the password is not sent again. When time runs out the page reloads to the sign-in screen.
- **Fixed** label “Tags cho devices” → “Device tags” in *Create registration token*.
- Agent **1.0.4**: MAC addresses; waits politely (every 5 minutes) while a re-enrolment is pending instead of giving up.

### 2.7.1 · 2026-11-11 · Simulated Wazuh for demo data
- **Added** demo-only source *Wazuh (simulated – demo data)*: 5 Wazuh agents (4 matched to demo endpoints, 1 unmatched) and 14 realistic CVE results incl. KEV, overdue and fixed ones, so every Vulnerabilities screen can be tried without a Wazuh server. Created once, only when `DEMO_DATA=true`; cannot be added from the UI.

### 2.7.0 · 2026-11-11 · CVE module, parts 4 + 5 – priority, deadlines, screens, alerts
- **Added** priority 0–100 (P1–P4) per finding from CVSS, KEV, ransomware use, EPSS and machine importance (Critical systems) – never from a source's score.
- **Added** patch deadlines (SLA) per (machine, CVE): clock starts on confirmation, tightens when a CVE enters KEV, restarts when a fixed CVE comes back; overdue / due soon / not started states and filters.
- **Added** *Vulnerabilities* tabs: Overview (stats, priority bars, 30-day trend, top machines / CVEs), Findings (priority + deadline columns, CSV export), By machine, By CVE, Sources, Policy; *CVEs* drawer lists **our machines** with that CVE.
- **Added** alerts for new confirmed KEV / P1 findings (one message per sync, each finding once) and a morning digest (overdue, due soon, new, KEV) through the existing notification channels.
- **Decision B** recorded (default deadlines, editable and audited).
- **Migration 0009** – `vuln_findings.priority`, `sla_category`, `sla_start`, `due_at`, `alerted_at`.

### 2.6.1 · 2026-11-10 · KEV download fix
- **Fixed** *CISA KEV failed*: when cisa.gov refuses the scripted download (403 from its CDN), the catalogue is taken from CISA's official copy on GitHub (`cisagov/kev-data`); the error lists every address tried.

### 2.6.0 · 2026-11-10 · CVE module, part 3 – vulnerabilities per machine
- **Added** *Operations → Vulnerabilities*: CVE × machine findings with catalogue severity, KEV, EPSS, package, confidence, first seen, status; filters, search, detail drawer with what each source reports.
- **Added** replaceable sources (`app/vulnsrc/`): **Wazuh** read-only adapter (server API + indexer `wazuh-states-vulnerabilities-*`, tested 4.14, format check, clear connection / TLS / permission errors), **file import** (CSV / JSON, Wazuh Discover export accepted), built-in **IT Ops CPE matching** for devices without an agent.
- **Added** safe host matching (serial → name → IP, unique only), unmatched-host list with manual mapping / ignore.
- **Added** triage: verify, false positive (reason), accepted risk (reason + review date) – audited, kept across source changes; *Compare sources* report for parallel runs; stale labels per source.
- **Changed** NVD sync keeps CPE version ranges and fetches CVEs reported by a source but missing from the catalogue; the next sync reloads the 120-day window once to fill the ranges.
- **Decision A** recorded in Roadmap (core + replaceable sources, rules, risks).
- **Migration 0008** – `vuln_sources`, `vuln_findings`, `vuln_detections`, `cves.cpe_match`.

### 2.5.0 · 2026-11-10 · CVE module, part 2 – CVE catalogue
- **Added** *Operations → CVEs*: new CVEs with CVSS severity, **CISA KEV** (exploited, ransomware use, due date), **EPSS** probability; filters (period, severity, KEV only), search by ID / product / text, sorting, detail drawer with vector, CWE, affected products and references.
- **Added** daily feed sync (`app/cve.py`): NVD API 2.0 (incremental by last-modified, 120-day backfill, all KEV CVEs), CISA KEV, FIRST EPSS; each feed is a pluggable `FeedSource`; per-feed status and *Sync now* (admin, audited).
- **Migration 0007** – `cves` table.

### 2.4.0 · 2026-11-10 · Wi-Fi clients
- **Added** Aruba Instant client list on SNMP checks: Name, IP, MAC, OS, ESSID, Access Point, **Signal** (Excellent → Poor), **Speed**; filter by ESSID, search, sort, weak-signal counter, likely-cause hints, scrolling list with fixed header.
- **Added** `backend/tools/snmp_test.py` for SNMP and Aruba diagnostics.
- **Added** README consolidated (setup, guides, reference, changelog) and a test that keeps it in step with the version.
- **Fixed** vendor detection when the sysObjectID is returned by name (`SNMPv2-SMI::enterprises.…`) – Aruba and ESXi.

### 2.3.0 · 2026-11-10 · English-first
- **Changed** UI to English; VN/EN switch kept but hidden.
- **Changed** every backend-generated text to English (alerts, events, check results, API errors, audit, automation, notifications) – logic unchanged.
- **Changed** built-in rules renamed in place on existing databases – IDs, settings and alert links kept, no duplicates.
- **Fixed** abnormal-RecordId rule and message, demo ARP rule, ESXi performance flag, map dependency edges, sidebar icons hidden by long labels.
- **Migration 0006** – English audit-trigger message. **Agent 1.0.3.**

### 2.2.0 · 2026-11-09 · CVE module, part 1
- **Added** Windows release / build / **UBR**, Linux release, macOS version.
- **Added** current user + source (console / RDP / SSH) and **last user**.
- **Added** reinstall-safe machine identity (MachineGuid / serial), normalized software, **data-quality** panel.
- **Fixed** agents sharing a NAT/VPN IP could take over each other's asset.
- **Migration 0005.** **Agent 1.0.2.**

### 2.1.0 · 2026-11-09 · Migration and parallel run
- **Added** import of the **running** v1 database (task 19), parallel-run mode, v1 ↔ v2 comparison report (task 20).
- **Fixed** Windows agent stopped after enrollment (folder permissions) – **agent 1.0.1**.

### 2.0.0 · 2026-11-07 → 08 · v2 platform
- **Changed** SQLite → **PostgreSQL 17** with Alembic migrations; new backup / restore.
- **Added** security P1: session cookies, idle timeout, admin **2FA**, AES-256-GCM, append-only 5W1H audit, SSH commands locked, HTTPS.
- **Added** realistic sample data, device simulator, light / dark theme, pinnable sidebar.
- **Added** endpoint agent (Windows / Linux / macOS) and *Endpoints* page.
- **Fixed** traps bypassing the IP filter via agentAddress.

### 1.x · until 2026-11-07 · original release (SQLite)
- Map, risk points, critical systems, sites, assets, checks, syslog / trap rules, alerts, audit, roles.
- Security monitoring: SLA, admin-action alerts, silent sources, hash-chained archive, production lock.
- Rules grouped by source IP, key filter, Windows Event Log by RecordId.
- Virtualization panel (ESXi, Proxmox, Hyper-V, Docker) with used / allocated.

---

## Other documents

| Document | About |
|---|---|
| [ADD-REAL-DEVICES.md](ADD-REAL-DEVICES.md) | Preparing real devices |
| [SECURITY-MONITORING.md](SECURITY-MONITORING.md) | Security monitoring use cases |
| [AUTOMATION.md](AUTOMATION.md) | Automation templates |
| [RUN-IN-VSCODE.md](RUN-IN-VSCODE.md) | Running from VS Code |
| [MIGRATE-TO-NEW-MACHINE.md](MIGRATE-TO-NEW-MACHINE.md) | Moving IT Ops to a new machine – step-by-step checklist |
| [SECURITY.md](SECURITY.md) | Security design of the tool |
| [DECISIONS/](DECISIONS/) | Architecture decisions |
| [agent/README.md](agent/README.md) | Agent deployment, HTTPS / CA pin, auto-update |
| [QA_REPORT.md](QA_REPORT.md) | QA history |
| [docs/BACKLOG.md](docs/BACKLOG.md) | Features to consider later – review each quarter |

*These documents are still in Vietnamese.*
