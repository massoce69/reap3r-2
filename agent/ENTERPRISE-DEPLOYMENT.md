# MASSVISION Reap3r Agent — Enterprise Deployment Guide

> **Version:** 1.2.0  
> **Compatibility:** Windows 7 SP1 → Windows Server 2025 (x86 + x64)  
> **Zero dependencies:** Static CRT, rustls TLS, no VC++ Redistributable, no OpenSSL

---

## Architecture

| Component | Technology | Notes |
|-----------|-----------|-------|
| TLS | rustls (pure-Rust) | TLS 1.2/1.3 on ANY Windows, no OS SChannel dependency |
| CRT | Static (`+crt-static`) | No `VCRUNTIME140.dll` or UCRT required |
| Service | `sc.exe` (Windows SCM) | Auto-start, auto-recovery |
| Logging | File + Windows Event Log | `%ProgramData%\Reap3r\logs\` + Event Viewer |
| CA Roots | Mozilla bundle (webpki-roots) | Works even if OS cert store is outdated |

## Compatibility Matrix

| OS Version | x64 | x86 | Service | Event Log | TLS 1.2 |
|------------|-----|-----|---------|-----------|---------|
| Windows 7 SP1 | ✅ | ✅ | ✅ | ✅ | ✅ (rustls) |
| Windows 8.1 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Windows 10 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Windows 11 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Server 2008 R2 SP1 | ✅ | ✅ | ✅ | ✅ | ✅ (rustls) |
| Server 2012 / R2 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Server 2016 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Server 2019 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Server 2022 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Server 2025 | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## 1. Building the Agent

### Prerequisites

```powershell
# Install Rust (if not present)
winget install Rustlang.Rustup

# Add both targets
rustup target add x86_64-pc-windows-msvc
rustup target add i686-pc-windows-msvc
```

### Build

```powershell
cd agent
.\build.ps1
```

This produces:
```
agent/dist/
  reap3r-agent-x64.exe   # 64-bit binary (~6-8 MB)
  reap3r-agent-x86.exe   # 32-bit binary (~6-8 MB)
  checksums.sha256        # SHA256 verification file
```

### Build Options

```powershell
.\build.ps1 -SkipX86        # Skip 32-bit build (if all machines are x64)
.\build.ps1 -Clean           # Clean dist/ before building
```

---

## 2. Building the Installer

### Prerequisites

Install [Inno Setup 6](https://jrsoftware.org/isdown.php) (free).

### Build

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" agent\installer\reap3r-agent.iss
```

Output: `agent/dist/reap3r-agent-setup-1.2.0.exe`

The installer automatically selects the correct architecture (x64 or x86) based on the target machine.

---

## 3. Installation Methods

### Method A: Interactive GUI Install

Double-click `reap3r-agent-setup-1.2.0.exe`. The wizard will prompt for:
1. Server URL (e.g., `wss://reap3r.yourcompany.com/ws/agent`)
2. Enrollment token

### Method B: Silent Install (GPO/SCCM/Intune)

```cmd
reap3r-agent-setup-1.2.0.exe /VERYSILENT /SERVER=wss://reap3r.company.com/ws/agent /TOKEN=your-enrollment-token
```

Parameters:
| Parameter | Description |
|-----------|-------------|
| `/VERYSILENT` | No UI at all |
| `/SILENT` | Minimal progress bar |
| `/SERVER=URL` | WebSocket URL of the backend |
| `/TOKEN=TOKEN` | One-time enrollment token |
| `/DIR="C:\Custom\Path"` | Custom install directory |
| `/LOG="C:\install.log"` | Log file for troubleshooting |

### Method C: Direct Binary (No Installer)

```cmd
:: Copy binary to target machine
copy reap3r-agent-x64.exe C:\Program Files\MASSVISION\Reap3r Agent\reap3r-agent.exe

:: Install as service with auto-enrollment
"C:\Program Files\MASSVISION\Reap3r Agent\reap3r-agent.exe" --install --server wss://reap3r.company.com/ws/agent --token YOUR_TOKEN
```

### Method D: PowerShell One-Liner (Remote)

```powershell
# Download + install in one command (for scripted deployments)
$url = "https://your-server/downloads/reap3r-agent-setup-1.2.0.exe"
$installer = "$env:TEMP\reap3r-setup.exe"
Invoke-WebRequest -Uri $url -OutFile $installer
Start-Process $installer -ArgumentList '/VERYSILENT','/SERVER=wss://reap3r.company.com/ws/agent','/TOKEN=YOUR_TOKEN' -Wait
Remove-Item $installer
```

---

## 4. GPO Deployment (Active Directory)

### Option A: Startup Script

1. Copy the installer to a network share: `\\DC\NETLOGON\reap3r\`
2. Create a GPO → Computer Configuration → Policies → Windows Settings → Scripts → Startup
3. Add script:

```cmd
@echo off
if exist "C:\Program Files\MASSVISION\Reap3r Agent\reap3r-agent.exe" exit /b 0
\\DC\NETLOGON\reap3r\reap3r-agent-setup-1.2.0.exe /VERYSILENT /SERVER=wss://reap3r.company.com/ws/agent /TOKEN=ENROLLMENT_TOKEN /LOG="C:\Windows\Temp\reap3r-install.log"
```

### Option B: Immediate Task (Preferred)

Create a GPO Scheduled Task (Immediate) that runs:
```cmd
reap3r-agent-setup-1.2.0.exe /VERYSILENT /SERVER=wss://... /TOKEN=...
```
- Run as: `SYSTEM`
- Run whether user is logged on or not
- Trigger: At task creation/modification

---

## 5. Intune / Endpoint Manager Deployment

1. Package the installer as a `.intunewin` file using the [IntuneWinAppUtil](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool)
2. Create a new Win32 app in Intune:
   - **Install command:** `reap3r-agent-setup-1.2.0.exe /VERYSILENT /SERVER=wss://reap3r.company.com/ws/agent /TOKEN=TOKEN`
   - **Uninstall command:** `"C:\Program Files\MASSVISION\Reap3r Agent\unins000.exe" /VERYSILENT`
   - **Detection rule:** File exists `C:\Program Files\MASSVISION\Reap3r Agent\reap3r-agent.exe`
   - **Requirements:** Windows 7 SP1 or later, Both x86 and x64

---

## 6. Zabbix Deployment

```
# Zabbix action → Remote command (executed on Zabbix agent)
powershell -NoProfile -Command "& {
  $url = 'https://your-server/downloads/reap3r-agent-setup-1.2.0.exe'
  $out = 'C:\Windows\Temp\reap3r-setup.exe'
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  (New-Object Net.WebClient).DownloadFile($url, $out)
  Start-Process $out -ArgumentList '/VERYSILENT','/SERVER=wss://reap3r.company.com/ws/agent','/TOKEN=TOKEN' -Wait
  Remove-Item $out
}"
```

---

## 7. Service Management

```cmd
:: Check status
sc query MASSVISION-Reap3r-Agent

:: Stop
sc stop MASSVISION-Reap3r-Agent

:: Start
sc start MASSVISION-Reap3r-Agent

:: Restart
sc stop MASSVISION-Reap3r-Agent && timeout /t 3 && sc start MASSVISION-Reap3r-Agent

:: View recovery configuration
sc qfailure MASSVISION-Reap3r-Agent

:: Uninstall
reap3r-agent.exe --uninstall
```

### Recovery Policy (Automatic)

The installer configures automatic restart on failure:
- **1st failure:** Restart after 5 seconds
- **2nd failure:** Restart after 10 seconds
- **3rd failure:** Restart after 30 seconds
- **Reset counter:** Every 24 hours
- **Non-crash exit handling:** Enabled (failureflag=1)

---

## 8. Diagnostics

```cmd
:: Full diagnostic report
reap3r-agent.exe --diagnose

:: Print loaded config
reap3r-agent.exe --print-config

:: View logs
type %ProgramData%\Reap3r\logs\agent.log

:: View Windows Event Log entries
wevtutil qe Application /q:"*[System[Provider[@Name='Reap3r Agent']]]" /c:20 /f:text
```

### Diagnostic Output Includes:
- OS version, hostname, architecture
- Windows version detail (from registry)
- TLS engine status (rustls, TLS 1.2/1.3)
- Static CRT confirmation
- Config file status
- Service status + recovery policy
- DNS resolution test
- HTTP health endpoint test
- WebSocket connection test
- Full compatibility matrix

---

## 9. Logging

### File Logs
- **Location:** `%ProgramData%\Reap3r\logs\agent.log`
- **Rotation:** Auto-rotate at 10 MB (keeps `.log.1` backup)
- **Format:** `[2025-01-01 12:00:00.000] [INFO ] message`

### Windows Event Log
- **Source:** `Reap3r Agent`
- **Log:** Application
- Critical events logged: service start/stop, enrollment, errors, warnings
- Integrates with: SIEM, Windows Event Forwarding, Azure Monitor

---

## 10. File Locations

| File | Path | Purpose |
|------|------|---------|
| Binary | `C:\Program Files\MASSVISION\Reap3r Agent\reap3r-agent.exe` | Agent executable |
| Config | `%ProgramData%\Reap3r\agent.conf` | Enrolled agent config (agent_id, hmac_key) |
| Bootstrap | `%ProgramData%\Reap3r\bootstrap.json` | Pre-install server/token (consumed on first start) |
| Log | `%ProgramData%\Reap3r\logs\agent.log` | Runtime log |
| Job History | `%ProgramData%\Reap3r\job_history.json` | Idempotent job tracking |
| Update Log | `%ProgramData%\Reap3r\update.log` | Self-update operation log |

---

## 11. Security Considerations

- The `agent.conf` file contains the HMAC key — access is restricted to SYSTEM/Administrators
- The agent runs as `LocalSystem` for full system management capabilities
- All communication is HMAC-signed (prevents tampering)
- TLS 1.2+ is enforced by default (rustls)
- Self-update verifies SHA256 hash before applying
- The agent never stores plaintext enrollment tokens after enrollment
