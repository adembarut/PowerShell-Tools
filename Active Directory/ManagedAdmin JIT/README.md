# ManagedAdmin JIT

**A secure, Event-Log driven Just-In-Time (JIT) Local Administrator solution for Windows, linked to Active Directory.**

This solution allows the **Owner** of a computer (defined by the `managedBy` attribute in Active Directory) to request temporary Local Administrator rights. It uses a strict, event-driven architecture to ensure rights are revoked automatically, regardless of system tampering.

---

## 🚀 Key Features

*   **AD-Linked Ownership:** access is *only* granted if the requesting user matches the `managedBy` field of the computer object in Active Directory.
*   **Immutable Expiration:** Access duration is calculated strictly from the `Member Added (Event 4732)` timestamp in the Windows Security Log. Users cannot extend their session by tampering with local files or system time.
*   **Zero-Delay Intruder Prevention:** A dedicated **Security Watchdog** triggers *instantly* upon any group addition. If the added user is not the authorized JIT user (or whitelisted), they are removed immediately.
*   **Smart Whitelisting:** Supports wildcard-based whitelisting (e.g., `*Domain Admins*`, `*HelpDesk*`) to protect permanent administrative groups.
*   **System Tray Integration:** A lightweight, non-intrusive tray application provides users with status updates and a "Request Access" button.

---

## 🛠 Architecture

The solution is deployed via a single "Golden Master" script (`Install-JIT.ps1`) which installs and configures the following components:

### 1. JIT-Core.ps1 (The Brain)
Located in `C:\Program Files\CorpIT\JIT\JIT-Core.ps1`. This script handles all logic:
*   Checking eligibility (AD `managedBy` attribute).
*   Granting access.
*   Enforcing time limits (Watchdog).
*   Monitoring for intruders.

### 2. Scheduled Tasks
The solution operates transparently using Windows Task Scheduler:
*   **`JIT-Check-Eligibility`**: Runs at `LogOn`. Checks if the current user is the "Owner" of the PC (via Active Directory `managedBy`).
*   **`JIT-Watchdog-Task`**: Runs every **5 minutes**. Scans the Administrators group and removes expired users.
*   **`JIT-Security-Monitor`**: **Event Triggered (ID 4732)**. Wakes up instantly when *anyone* is added to Administrators to validate and sanitize the group.
*   **`JIT-Tray-App`**: Runs at `LogOn`. Provides the GUI.

---

## 📦 Installation Guide

### Prerequisites
*   Windows 10 / 11 or Windows Server 2016+.
*   PowerShell 5.1 (Default on Windows).
*   Active Directory Environment (The script checks the `managedBy` attribute of the computer object).

### Deployment
1.  **Download** the `Install-JIT.ps1` script to the target machine.
2.  **Run as Administrator**:
    ```powershell
    Powershell.exe -ExecutionPolicy Bypass -File .\Install-JIT.ps1
    ```
3.  **Verify**:
    *   Check if the folder `C:\Program Files\CorpIT\JIT` exists.
    *   Check if the "JIT Admin" tray icon appears (you may need to re-log or run the tray app manually once).

---

## ⚙️ Configuration

All configuration is managed within the `JIT-Core.ps1` block inside the installer. To change settings, edit `Install-JIT.ps1` before deployment.

### 1. Duration (Session Length)
Defines how long (in minutes) a user remains an administrator.
```powershell
$Duration = 30  # Default: 30 Minutes
```

### 2. Whitelist (Permanent Admins)
Users or Groups who should **NEVER** be removed by the watchdog. Supports wildcards.
```powershell
$Whitelist = @(
    "Administrator",       # Built-in local admin
    "Domain Admins",       # Domain Admins group
    "Tier 2 Support",      # Specific Helpdesk group
    "*GPP*"                # Any group matching *GPP* (e.g. DOMAIN\GPP_LocalAdmins)
)
```

---

## 📝 Troubleshooting & Logs

**Log File Location:** `C:\ProgramData\CorpIT\JIT\Service.log`

### Common Log Messages
*   **GRANTED:** User successfully added.
*   **CHECK:** Watchdog ran, user is still within time limits.
*   **ENFORCEMENT:** Time expired, user removed.
*   **SECURITY VIOLATION:** Unauthorized user detected and removed.
*   **GRANT DENIED:** User requested access but is not the eligible owner (AD check failed).

To debug "Unauthorized" issues, check the log for:
`AD USER [X] does not match CURRENT USER [Y]`

---

## 🗑 Uninstallation

To completely remove the solution:
1.  Open PowerShell as Administrator.
2.  Delete the program folder: `Remove-Item "C:\Program Files\CorpIT" -Recurse -Force`
3.  Unregister Scheduled Tasks:
    ```powershell
    Unregister-ScheduledTask -TaskName "JIT-Check-Eligibility" -Confirm:$false
    Unregister-ScheduledTask -TaskName "JIT-Watchdog-Task" -Confirm:$false
    Unregister-ScheduledTask -TaskName "JIT-Elevate-Task" -Confirm:$false
    Unregister-ScheduledTask -TaskName "JIT-Security-Monitor" -Confirm:$false
    Unregister-ScheduledTask -TaskName "JIT-Tray-App" -Confirm:$false
    ```
