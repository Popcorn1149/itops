# IT Ops Agent (Go)

The agent runs on each workstation or server. It **only reads** machine information and **only sends data up** to IT Ops Workspace. It accepts no commands from the server (see `DECISIONS/0004`).

| | Windows | Linux | macOS |
|---|---|---|---|
| Runs as | Windows Service `ITOpsAgent` (LocalSystem) | systemd `itops-agent` | launchd `vn.itops.agent` |
| Performance | CPU, RAM, fixed drives | CPU, RAM, real partitions ≥ 1 GB | CPU, RAM, APFS |
| Events | Event Log (wevtapi), only Event IDs in the policy | journald (sshd, sudo, useradd/usermod, kernel, systemd) | unified log (sshd, sudo) |
| Security | Defender, BitLocker, firewall, latest patch | firewall (ufw/firewalld), pending reboot | FileVault, firewall, Gatekeeper, SIP |
| Services / software | SCM / Uninstall registry (machine + each user) | systemctl / dpkg, rpm, snap | launchctl / system_profiler |
| Test status | Run on **Wine** (see below); event log + Defender not yet tested on real Windows | **run for real** against an HTTPS server | Command parsers tested on real-format macOS output; not yet run on a Mac |

**What it does NOT do:** run remote commands, install or remove software, read user files, take screenshots, log keystrokes, or collect normal logon/logoff events.

## Try it without installing: `simulate`
Simulates several Windows/macOS machines sending data to the server. No admin rights needed, nothing gets installed.

The raw data is built in exactly the format each OS produces:
- Windows Event Log XML;
- macOS output from `launchctl`, `system_profiler`, `top`, `vm_stat` and `log show`.

That data then goes through **the same parsing functions and the same send path** as the real agent: registration, on-disk queue, HTTPS/`ca_pin`.
```
itops-agent-windows-amd64.exe simulate --server http://127.0.0.1:8100 --allow-http --token itk_xxx --windows 3 --macos 2
```
The token needs at least 5 uses. Machine names: SIM-SRV01, SIM-WIN02, SIM-WIN03, SIM-MAC01…

Built-in scenarios:
- RDP password guessing against SIM-SRV01, followed by an account lockout;
- someone added to Administrators;
- a dead backup service;
- malware on SIM-WIN03;
- Defender switched off on SIM-WIN02;
- data drive D: almost full;
- SSH password guessing and wrong sudo passwords on the Macs.

Stop with Ctrl+C. Run it again and the same machines are reused, no duplicates.

VS Code: task **17**.

### Already verified on Wine (Windows 10 emulation on Linux, running the actual `itops-agent-windows-amd64.exe`)
- `install`: copies into Program Files, registers, creates the `ITOpsAgent` service and **runs as a service**. `net stop`/`net start` and `uninstall --purge` work.
- Reinstalling with a **wrong token** on a working machine keeps the old configuration, and the machine keeps running.
- Reads Windows version, CPU, RAM, drives, logged-in user, the 17 services, and software from the registry (64-bit, 32-bit, per user; Windows updates and hidden components filtered out).
- **Self-update** while running as a service: 1.0.0 → 1.0.1. The service manager restarts the new version, and the server sees 1.0.1.
- Bugs found and fixed on Wine:
  - service creation failed on systems without delayed start;
  - the agent didn't recognise it was running as a service;
  - a wrong token wiped the key of a working machine;
  - CPU sampling could loop forever.
- **Not tested on Wine:** the Event Log (Wine doesn't implement `EvtQuery`) and Defender/BitLocker (Wine has no PowerShell). These two parts get their first real run on a real Windows machine.

## Install

Every file is at **Máy trạm → Cài đặt agent** (download, SHA-256 hash, and ready-made commands with the token and `ca_pin` filled in).

1. Create a **registration token** (Máy trạm → Cài đặt agent → Tạo token). The token is shown once. It is only used to register: each machine then gets its own key, so an expired token does not affect machines that are already installed.
2. Install:

**Windows, single machine** (PowerShell *Run as administrator*):
```
.\itops-agent-windows-amd64.exe install --server https://itops.cty.local:8443 --token itk_xxx --ca-pin <sha256>
```

**Windows, 50–200 machines via GPO:**
1. Create the share `\\FILESERVER\itops$`. Give **Domain Computers: Read** and **IT admins only: Write**. Anyone who can write an .exe here can run code as SYSTEM on every machine.
2. Copy into it: `itops-agent-windows-amd64.exe`, `install-windows.ps1`, `SHA256SUMS.txt`.
3. GPO → Computer Configuration → Policies → Windows Settings → Scripts → **Startup** → PowerShell Scripts:
   - Script: `\\FILESERVER\itops$\install-windows.ps1`
   - Parameters: `-Server https://itops.cty.local:8443 -Token itk_xxx -CaPin <sha256> -Source \\FILESERVER\itops$\itops-agent-windows-amd64.exe`
4. The script runs at every boot:
   - Already installed at the right version → it skips.
   - New version on the share → it upgrades.
   - It checks the SHA-256 before installing.
   - Log: `C:\Windows\Temp\itops-agent-install.log`.

**Linux:** `sudo ./install-linux.sh https://itops.cty.local:8443 itk_xxx <ca_pin>`

**macOS:** `sudo ./install-macos.sh https://itops.cty.local:8443 itk_xxx <ca_pin>`. The file is not signed (no Apple Developer ID), so copy it by USB/scp. If you download it through a browser, Gatekeeper blocks it.

### HTTPS and `ca_pin` (with or without AD CS)
- **AD CS available:** issue the server a certificate from the internal CA. Machines in the domain trust it automatically, so `--ca-pin` is not needed.
- **No AD CS:** the server uses a self-signed certificate (`admin_tools gen-cert`). Pass `--ca-pin`, which is the SHA-256 of the certificate's public key. The agent then accepts only that exact key, so a fake server on the LAN cannot capture data or a key. The Cài đặt agent page fills in the pin automatically. If you renew the certificate with the same key, the pin stays the same; if you change the key, you must reinstall with the new pin.
- **`--allow-http`** is **for demo only**: the machine key travels in plain text.

### Unsigned files (no code signing certificate)
SmartScreen/Defender may warn when you run the file by hand. Installing via GPO (startup script running as SYSTEM) does not prompt. Always compare the SHA-256 with `SHA256SUMS.txt` before putting files on the share.

## Checking and removing
```
itops-agent status          # server, machine ID, number of queued reports, revoked or not
itops-agent collect         # print everything it collects (sends nothing) – run as admin/root to see the full set
itops-agent pin --server https://itops.cty.local:8443
itops-agent uninstall [--purge]
```

Data and logs are kept here, readable only by SYSTEM/Administrators or root:
- Windows: `C:\ProgramData\ITOpsAgent`
- Linux: `/var/lib/itops-agent`
- macOS: `/Library/Application Support/ITOpsAgent`

Logs rotate automatically, 2 × 5 MB at most.

If the network or server is down, reports stay in the `spool/` queue (up to 2,000 reports, about 1.5 days) and are sent in order once the connection returns.

## Self-update (optional, signed)
The server **only relays** the release. The agent checks the Ed25519 signature against the public key in `agent.json`, which was set at install time. Someone who takes over the server still cannot push a fake binary down to the machines.

1. **Once**, on the admin's machine (not on the server), create the signing key:
   ```
   itops-agent-release.exe keygen --out D:\khoa-agent
   ```
   Store the private key `update-signing.key` offline (USB or safe).
2. Install agents with `--update-pubkey <public key>` (GPO: `-UpdatePubKey`).
3. Release a new version:
   ```
   ./scripts/build.sh 1.0.1
   itops-agent-release sign --key update-signing.key --version 1.0.1 --dir dist
   ```
   Copy `manifest.json` and the `itops-agent-*` files into `<DATA_DIR>/agent-updates/` on the server, then turn on **Tự cập nhật** in Cài đặt agent.
4. The agent:
   - only upgrades to a higher version, never downgrades;
   - checks the SHA-256 of the downloaded file;
   - swaps the file in and restarts itself.

## Build (no Internet needed)
`golang.org/x/sys` is already in `vendor/`. You need Go ≥ 1.24.

```
./scripts/build.sh 1.0.0     # → dist/ (Windows/Linux/macOS amd64+arm64) + SHA256SUMS.txt
go test ./...
```
