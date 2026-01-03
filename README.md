# PowerShell-Tools

### Advanced PowerShell automation scripts for IT Infrastructure

A collection of production-ready, highly reliable PowerShell modules and scripts designed to streamline complex infrastructure management tasks.

Key focus areas include:
* **Active Directory deep dives**
* **Group Policy automation**
* **Azure/M365 reporting**
* **Graphical data visualization**

---

## 🛠️ Tools & Scripts Overview

| Tool / Module | Description | Key Features |
| :--- | :--- | :--- |
| **[Export-ADStructureToVisio.ps1](./Active Directory/AD Topology/Export-ADStructureToVisio.ps1)** | Automates the visualization of the Active Directory OU and GPO structure into a hierarchical Microsoft Visio diagram. Eliminates manual mapping, providing a clean, accurate, and scalable infrastructure documentation layer. | - **OU Hierarchy Mapping**<br>- **GPO Link Visualization** (Grouped or Standard)<br>- **Object Counting:** Displays User, Computer, and Group totals per OU (recursive).<br>- **Visio Automation** (Requires Visio client). |
| **[Install-JIT.ps1](./Security/Local Admin/Install-JIT.ps1)** | A secure, **Just-In-Time (JIT)** Local Administrator access system. Allows eligible users to request temporary admin rights via a System Tray app, ensuring least-privilege compliance with strict auditing and automatic cleanup. | - **Hybrid Architecture:** Zero-resource usage (Event-Driven & Delayed Tasks).<br>- **Smart Security Watchdog:** Monitors Event ID 4732 to instantly detect and revert unauthorized manual admin additions.<br>- **AD Integration:** Validates eligibility via `managedBy` attribute using `.NET` (No RSAT dependency).<br>- **Robust Lifecycle:** Handles reboots, shutdowns, and crashes; ensures admin rights are revoked exactly when expired.<br>- **Silent Operation:** Includes VBS wrapper for hidden execution. |
