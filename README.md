# PowerShell-Tools
Advanced PowerShell automation scripts for IT Infrastructure

A collection of production-ready, highly reliable PowerShell modules and scripts designed to streamline complex infrastructure management tasks. Key focus areas include **Active Directory deep dives, Group Policy automation, Azure/M365 reporting, and graphical data visualization.**

---

## Tools & Scripts Overview

| Tool / Module | Description | Key Features |
| :--- | :--- | :--- |
| **[`Export-ADStructureToVisio.ps1`](./Active Directory/AD Topology/Export-ADStructureToVisio.ps1)** | **Automates the visualization of the Active Directory OU and GPO structure** into a hierarchical Microsoft Visio diagram. Eliminates manual mapping, providing a clean, accurate, and scalable infrastructure documentation layer. | - **OU Hierarchy Mapping** <br> - **GPO Link Visualization** (Grouped or Standard) <br> - **Object Counting:** Displays User, Computer, and Group totals per OU (recursive). <br> - **Visio Automation** (Requires Visio client). |

---

### Yapılan Değişiklik:

* **Link Yolu:** Scriptin adı etrafındaki köprü (`[...]`) kısmı, yeni klasör yapınızı yansıtacak şekilde güncellendi:
    * Eski Yol: `./AD-Visio-Mapper/Export-ADStructureToVisio.ps1`
    * **Yeni Yol:** `./Active Directory/AD Topology/Export-ADStructureToVisio.ps1`

Bu yapı artık hem mantıksal olarak doğru klasörleri kullanıyor hem de profesyonel görünüyor.

Başka bir script eklediğinizde, sadece tabloya yeni bir satır ekleyerek ve klasör yolunu belirterek bu listeyi kolayca genişletebilirsiniz. Başarılar dilerim!
