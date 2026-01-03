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
| **[Install-JIT.ps1](./Install-JIT.ps1)** | **JIT Admin Solution".** An enterprise-grade Local Administrator access system designed to be deployed via **GPO Startup Scripts**. It enforces a Zero Trust model by monitoring Security Event Logs and automatically revoking unauthorized admin rights. | - **GPO Startup Ready:** Optimized execution logic for deployment via `Computer Configuration > Scripts > Startup`.<br>- **SID-Based Authority:** Uses `S-1-5-32-544` checks ensuring compatibility with Multi-language OS (TR/EN).<br>- **Event Log Watchdog:** Monitors Event ID 4732 to instantly detect and revert unauthorized admin additions.<br>- **Race Condition Protection:** Prevents state conflicts during rapid grant/revoke cycles.<br>- **Diagnostic Logging:** Generates detailed audit trails in `C:\ProgramData\CorpIT\JIT\Service.log`. |
