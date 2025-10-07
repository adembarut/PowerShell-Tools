#############################################################################
# Script Name: Export-ADStructureToVisio
# Sürüm      : 8.13 - KRİTİK DÜZELTME: IncludeGPOs Parametresi [bool] yapıldı.
# Purpose    : Active Directory OU ve GPO yapısını Visio'ya hiyerarşik olarak
#            haritalar, nesne sayılarını görselleştirir.
#
# Editor     : Adem Barut
# Title      : Altyapı ve Sistem Mimarı
# Company    : Türksat Uydu Haberleşme Kablo TV ve İşletme A.Ş.
#############################################################################

<#
.SYNOPSIS
Active Directory OU ve GPO yapısını Visio'ya çizer ve kritik AD verilerini (nesne sayıları) görselleştirir.

--- ÖN KOŞULLAR VE KURULUM TALİMATLARI ---

1. GEREKSİNİMLER:
   - Bu scriptin çalıştırıldığı Windows 11 makinesinde **Microsoft Visio** kurulu olmalıdır.

2. POWERHSHELL MODÜLLERİNİN KURULUMU:
   Bu script, üç ana modül kullanır: ActiveDirectory, GroupPolicy ve Visio (VisioAutomation).

   A) RSAT Modülleri (Active Directory & Group Policy):
      Windows 11 Ayarlar uygulamasından 'İsteğe bağlı özellikler' aracılığıyla veya Yönetici PowerShell'de şu komutlarla kurulur:
      Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
      Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0

   B) VISIO Modülü (VisioAutomation):
      Bu modül Visio uygulamasını kontrol eder. Yönetici PowerShell'de kurulur:
      **Install-Module -Name Visio**

3. İZİN VE AYARLAR:
   - Script, Active Directory verilerini okuma iznine sahip bir **Domain User** hesabı ile çalıştırılmalıdır.
   - Scripti çalıştırmadan önce, **Execution Policy** ayarının 'RemoteSigned' veya daha gevşek olduğundan emin olun (Örn: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser).
   - Scriptin sonundaki '$CustomParams' bloğundaki **ADStencilPath** değerini, Visio şablon dosyanızın (.vss) tam yolu ile güncelleyin.

.PARAMETER LayoutDirection
Visio haritasının düzen yönünü belirtir. Olası değerler: "LeftToRight" (Varsayılan) veya "TopToBottom".

.PARAMETER IncludeGPOs
Haritaya Group Policy Objects (GPO) bağlantılarını dahil edip etmeyeceğinizi belirtir. ($true/ $false)

.PARAMETER GroupLinkedGPOs
$true olarak ayarlanırsa, aynı OU'ya bağlı GPO'ları tek bir grup şekli altında numaralandırır. $false (Varsayılan) ise her GPO'yu ayrı bir şekil olarak çizer.

.PARAMETER IncludeObjectCounts
Her bir OU için içerdiği Kullanıcı, Bilgisayar ve Grup sayılarını (alt OU'lar dahil) alır ve OU şeklinin metnine ekler.
.PARAMETER ADStencilPath
Active Directory şekillerini içeren Visio Şablon (Stencil) dosyasının tam yolu.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("TopToBottom", "LeftToRight")]
    [string]$LayoutDirection = "LeftToRight", 

    [Parameter(Mandatory=$false)]
    # KRİTİK DÜZELTME: Artık [bool]
    [bool]$IncludeGPOs = $true,  
    
    [Parameter(Mandatory=$false)]
    [bool]$GroupLinkedGPOs = $false, 
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeObjectCounts = $true, 

    [Parameter(Mandatory=$false)]
    [string]$ADStencilPath = "C:\Users\Administrator\Documents\Şekillerim\Active Directory Nesneleri.vss"
)

# --- Global Veri Yapıları ---
# Gruplama için GPO listesi
$Script:GPOList = New-Object System.Collections.ArrayList
$Script:globalGpoNum = 0 
$Script:conCount = 0
$Script:gpoShapeNum = 0 # Ayrı çizimler için tekil isim sayacı

# -----------------------------------------------------------------------------
# BÖLÜM 1: YARDIMCI VE ÇİZİM STİLİ FONKSİYONLARI 🎨
# -----------------------------------------------------------------------------

function Get-GPOConnectionStyleCells {
    $con_cells = New-VisioShapeCells
    $con_cells.LineColor = "rgb(0,175,240)"; $con_cells.LineEndArrowSize = "3"
    $con_cells.LineBeginArrowSize = "2"; $con_cells.LineEndArrow = "42" 
    $con_cells.LineBeginArrow = "4"; $con_cells.CharColor = "rgb(0,175,240)"
    return $con_cells
}

function Set-VisioGPOProperties {
    # Hyperlinkler kaldırıldı, sadece temel GPO özelliklerini ekler.
    param([object]$ShapeGPO, [Microsoft.GroupPolicy.Gpo]$GPO)
    $GUID = "{" + $GPO.id.guid + "}"
    Set-VisioCustomProperty -Shape $ShapeGPO -Name "GPOName" -Value $GPO.DisplayName
    If ($GPO.ID.Guid) { Set-VisioCustomProperty -Shape $ShapeGPO -Name "GUID" -Value $GUID }
    If ($GPO.GPOStatus) { Set-VisioCustomProperty -Shape $ShapeGPO -Name "Status" -Value $GPO.GpoStatus.ToString() }
}

function Add-GPOToGlobalList {
    # Gruplandırılmış çizim için GPO'ları global bir listeye ekler veya günceller.
    param([Microsoft.GroupPolicy.Gpo]$GPO, [string]$LinkLocation)
    $existingGpo = $Script:GPOList | Where-Object {$_.GUID -eq $GPO.Id.Guid}
    
    if (-not $existingGpo) {
        $Script:globalGpoNum += 1
        $gpoEntry = [PSCustomObject]@{
            Number = $Script:globalGpoNum;
            DisplayName = $GPO.DisplayName;
            GUID = $GPO.Id.Guid;
            LinkedTo = @($LinkLocation);
        }
        [void]$Script:GPOList.Add($gpoEntry)
        return $Script:globalGpoNum
    } else {
        if ($existingGpo.LinkedTo -notcontains $LinkLocation) {
            $existingGpo.LinkedTo += $LinkLocation
        }
        return $existingGpo.Number
    }
}

function Draw-GPOs-Standard {
    # GPO'ları her bir OU'nun yanına ayrı şekiller olarak çizer.
    param([object]$TargetShape, [array]$GpoLinks, [object]$MasterGPO,
          [object]$Connector, [string]$DNSDomain, [string]$CanonicalPath)
    
    ForEach ($gpolink in $GpoLinks) {
        $gpoGUID = ([Regex]::Match($gpolink, '{[a-zA-Z0-9]{8}[-][a-zA-Z0-9]{4}[-][a-zA-Z0-9]{4}[-][a-zA-Z0-9]{4}[-][a-zA-Z0-9]{12}}')).Value
        if (-not $gpoGUID) { Continue }

        try { $gpo = Get-GPO -Guid $gpoGUID -Domain $DNSDomain }
        catch { Write-Warning "GPO alınırken hata oluştu. Atlanıyor."; Continue }
        
        $Script:gpoShapeNum += 1; $Script:conCount += 1
        $shapenameGPO = "g" + $Script:gpoShapeNum
        
        $shapeGPO = New-VisioShape -Master $MasterGPO -Position (New-VisioPoint -X 1.0 -Y 1.0) 
        $ShapeGPO.Text = $GPO.DisplayName; $ShapeGPO.Name = $shapenameGPO
        
        Set-VisioGPOProperties -ShapeGPO $shapeGPO -GPO $gpo
        
        $con = Connect-VisioShape -From $TargetShape -To $shapeGPO -Master $Connector
        $con.Text = "GPO"; $con.Name = "gcon" + $Script:conCount
        Set-VisioShapeCells -Cells (Get-GPOConnectionStyleCells) -Shape $con
    }
}

function Draw-GPOs-Grouped {
    # GPO'ları tek bir grup şekli altında listeler ve numaralandırır.
    param([object]$TargetShape, [array]$GpoLinks, [object]$MasterGPO,
          [object]$Connector, [string]$DNSDomain, [string]$CanonicalPath)
    
    $GpoNumbers = @()
    Write-Host "-> $CanonicalPath için GPO'lar gruplanıyor ve numaralandırılıyor (GRUPLU)..." -ForegroundColor DarkYellow
    
    ForEach ($gpolink in $GpoLinks) {
        $gpoGUID = ([Regex]::Match($gpolink, '{[a-zA-Z0-9]{8}[-][a-zA-Z0-9]{4}[-][a-zA-Z0-9]{4}[-][a-zA-Z0-9]{4}[-][a-zA-Z0-9]{12}}')).Value
        if (-not $gpoGUID) { Continue }

        try { $gpo = Get-GPO -Guid $gpoGUID -Domain $DNSDomain }
        catch { Write-Warning "GPO alınırken hata oluştu. Atlanıyor."; Continue }
        
        $GpoNumbers += Add-GPOToGlobalList -GPO $gpo -LinkLocation $CanonicalPath
    }
    
    if ($GpoNumbers.Count -gt 0) {
        $Script:conCount += 1
        $GpoNumbersText = ($GpoNumbers | Sort-Object -Unique) -join "," 
        
        $GroupShape = New-VisioShape -Master $MasterGPO -Position (New-VisioPoint -X 1.0 -Y 1.0)
        $GroupShape.Text = "GPOs: [$GpoNumbersText]"  
        $GroupShape.Name = "g_group_" + $CanonicalPath.Replace('/', '_').Replace('.', '_')
        
        $con = Connect-VisioShape -From $TargetShape -To $GroupShape -Master $Connector
        $con.Text = "GPO Bağlantıları"; $con.Name = "gcon" + $Script:conCount
        Set-VisioShapeCells -Cells (Get-GPOConnectionStyleCells) -Shape $con
        
        Set-VisioCustomProperty -Shape $GroupShape -Name "GPO_Numbers" -Value $GpoNumbersText
        Set-VisioCustomProperty -Shape $GroupShape -Name "Linked_OU" -Value $CanonicalPath
    }
}

function Draw-RootGPOs {
    # Kök alana (Domain) bağlı GPO'ları çizer.
    param([object]$RootDomainShape, [array]$RootGPOs, [object]$MasterGPO,
          [object]$Connector, [string]$DNSDomain, [bool]$GroupLinkedGPOs)
    
    Write-Host "Kök alana bağlı GPO'lar işleniyor..." -ForegroundColor Yellow
    $GpoLinks = $RootGPOs.gPlink -split "\]\[" | Where-Object { $_ -match '{[a-zA-Z0-9]{8}[-][a-zA-Z0-9]{4}[-][a-zA-Z0-9]{4}[-][a-zA-Z0-9]{4}[-][a-zA-Z0-9]{12}}' }

    if (-not $GpoLinks) { Write-Host "-> Kök alanda bağlı GPO bulunamadı." -ForegroundColor DarkGray; return }

    $CanonicalPath = $DNSDomain
    
    if ($GroupLinkedGPOs) {
        Draw-GPOs-Grouped -TargetShape $RootDomainShape -GpoLinks $GpoLinks -MasterGPO $MasterGPO -Connector $Connector -DNSDomain $DNSDomain -CanonicalPath $CanonicalPath
    } else {
        Draw-GPOs-Standard -TargetShape $RootDomainShape -GpoLinks $GpoLinks -MasterGPO $MasterGPO -Connector $Connector -DNSDomain $DNSDomain -CanonicalPath $CanonicalPath
    }
}

# -----------------------------------------------------------------------------
# BÖLÜM 2 & 3: VERİ ALMA VE HİYERARŞİ ÇİZİM FONKSİYONLARI
# -----------------------------------------------------------------------------

function Import-RequiredModules {
    # Scriptin çalışması için gerekli PowerShell modüllerini yükler.
    Write-Host "Gerekli modüller içe aktarılıyor..." -ForegroundColor Green
    Try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module Visio -ErrorAction Stop
    }
    Catch {
        Write-Error "Gerekli modüller içe aktarılırken hata oluştu. Lütfen RSAT ve Visio modüllerinin kurulu olduğundan emin olun."
        Read-Host "Çıkmak için herhangi bir tuşa basın"; exit 1
    }
}

function Get-ADData {
    # Active Directory'den OU ve Kök Alan GPO verilerini çeker.
    param([string]$DNSDomain, [switch]$IncludeObjectCounts)
    Write-Host "Oluşum Birimleri (OU'lar) $DNSDomain alanından alınıyor..." -ForegroundColor Yellow
    try {
        $OUProps = "Name", "DistinguishedName", "CanonicalName", "LinkedGroupPolicyObjects"
        
        # gPLinkOptions KALDIRILDI
        $OUs = Get-ADOrganizationalUnit -Server $DNSDomain -Filter 'Name -like "*"' -Properties $OUProps -ErrorAction Stop | 
                Where-Object {$_.canonicalname -notlike "*LostandFound*"} | 
                Select-Object Name, Canonicalname, DistinguishedName, LinkedGroupPolicyObjects, @{Name='Depth';Expression={($_.CanonicalName -split '/').Count}} | 
                Sort-Object Depth, CanonicalName 

        # Nesne sayımı ekle
        if ($IncludeObjectCounts) {
            Write-Host "OU nesne sayıları hesaplanıyor..." -ForegroundColor DarkYellow
            $UpdatedOUs = @()
            
            foreach ($ou in $OUs) {
                $ouPath = $ou.DistinguishedName
                
                # @(...) Kullanımı ile tekil nesne sayım hataları giderildi.
                $userCount = @(Get-ADUser -Filter * -SearchBase $ouPath -SearchScope Subtree -ErrorAction SilentlyContinue).Count
                $computerCount = @(Get-ADComputer -Filter * -SearchBase $ouPath -SearchScope Subtree -ErrorAction SilentlyContinue).Count
                $groupCount = @(Get-ADGroup -Filter * -SearchBase $ouPath -SearchScope Subtree -ErrorAction SilentlyContinue).Count
                
                $ou | Add-Member -MemberType NoteProperty -Name UserCount -Value $userCount -Force
                $ou | Add-Member -MemberType NoteProperty -Name ComputerCount -Value $computerCount -Force
                $ou | Add-Member -MemberType NoteProperty -Name GroupCount -Value $groupCount -Force
                
                $UpdatedOUs += $ou
            }
            $OUs = $UpdatedOUs
        }
        
        # Kök alan GPO'ları çekilir
        # gPLinkOptions KALDIRILDI
        $RootGPOs = Get-ADObject -Server $DNSDomain -Identity (Get-ADDomain -Identity $DNSDomain).distinguishedName -Properties name, distinguishedName, gPLink, gPOptions -ErrorAction Stop

        return @{ OUs = $OUs; RootGPOs = $RootGPOs }
    }
    catch {
        Write-Error "$DNSDomain alanından AD verileri alınırken KRİTİK HATA oluştu: $($_.Exception.Message)"
        Read-Host "Çıkmak için herhangi bir tuşa basın"; exit 1
    }
}

function Initialize-VisioMasters {
    # Visio şablonunu açar ve gerekli ana şekilleri (Master Shapes) alır.
    param([string]$ADStencilPath)
    Write-Host "Visio şablonları yükleniyor ve Master şekilleri alınıyor..." -ForegroundColor Cyan
    try {
        if (-not (Test-Path $ADStencilPath)) {
            throw "Active Directory şablon dosyası bulunamadı: $ADStencilPath. Lütfen yolu kontrol edin."
        }

        $ADO_u = Open-VisioDocument $ADStencilPath
        $connectors = Open-VisioDocument "Connectors.vss"

        $masters = @{
            masterOU = Get-VisioMaster -Document $ADO_u | Where-Object {$_.NameU -eq "Organizational unit"}
            masterDomain = Get-VisioMaster -Document $ADO_u | Where-Object {$_.NameU -eq "Domain"}
            masterGPO = Get-VisioMaster -Document $ADO_u | Where-Object {$_.NameU -eq "Policy"}
            connector = Get-VisioMaster -Document $connectors | Where-Object {$_.NameU -eq "Dynamic connector"} 
        }
        
        if ($masters.masterOU -and $masters.masterDomain -and $masters.masterGPO -and $masters.connector) {
            Write-Host "Master şekiller başarıyla yüklendi." -ForegroundColor Green
            return $masters
        } else {
            throw "Kritik Master şekillerinden biri veya daha fazlası bulunamadı (OU, Domain, Policy veya Connector)."
        }
    }
    catch {
        Write-Error "Visio şekilleri alınırken kritik hata oluştu: $($_.Exception.Message)"
        Read-Host "Çıkmak için herhangi bir tuşa basın"; exit 1
    }
}

function Draw-OUHierarchy {
    # OU'ları hiyerarşik sırada çizer, üst OU'ya bağlar ve GPO'ları işler.
    param([array]$OUs, [object]$RootDomainShape, [object]$MasterOU, [object]$MasterGPO, 
          [object]$Connector, [string]$DNSDomain, 
           # KRİTİK DÜZELTME: Artık [bool]
           [bool]$IncludeGPOs, 
           [bool]$GroupLinkedGPOs,
          [switch]$IncludeObjectCounts)
    
    Write-Host "OU şekilleri oluşturuluyor ve hiyerarşik olarak bağlanıyor..." -ForegroundColor Yellow
    $localOUStep = 0.0

    ForEach ($ou in $OUs) {
        $localOUStep += 0.1 
        $OUConName = $ou.Canonicalname
        
        $pathSegments = $OUConName -split '/'
        $parentSegments = $pathSegments[0..($pathSegments.Count - 2)]
        $parentPath = $parentSegments -join '/' 
        $prevOUName = "n" + $parentPath

        $shapename = "n" + $OUConName; 
        $ParentShape = $null; 
        $IsRootLevelOU = $parentSegments.Count -eq 1 

        # Üst Şekli Bul (Domain veya Üst OU)
        If ($IsRootLevelOU) { $ParentShape = $RootDomainShape }
        else {
            $ParentShape = Get-VisioShape -Name $prevOUName -ErrorAction SilentlyContinue
            If (-not $ParentShape) { 
                Write-Warning "UYARI: '$ou.Name' için Üst OU şekli '$prevOUName' bulunamadı. Bağlantı atlanıyor (Şekil çizilecek)."
                # Şekil oluşturma ve alt akış devam ediyor.
            } 
        }
        
        # YENİ OU ŞEKLİNİ OLUŞTUR
        $shape = New-VisioShape -Master $MasterOU -Position (New-VisioPoint -X (1.0 + $localOUStep) -Y (1.0 + $localOUStep))
        if (-not $shape) { Write-Warning "Yeni OU şekli oluşturulamadı."; Continue }
        
        $OUText = $ou.Name
        $Shape.Text = $OUText; $Shape.Name = $shapename

        # Nesne Sayımı Ekle
        if ($IncludeObjectCounts -and $ou.UserCount -ne $null) {
            $counts = "K:$($ou.UserCount) / B:$($ou.ComputerCount) / G:$($ou.GroupCount)"
            Set-VisioCustomProperty -Shape $shape -Name "Nesne_Sayımı" -Value $counts
            $Shape.Text = $shape.Text + "`n" + $counts
        }

        # Üst Şekle Bağla (ParentShape varsa bağlantı yapılır)
        If ($ParentShape) { Connect-VisioShape -From $ParentShape -To $shape -Master $Connector | Out-Null }

        # Bağlı GPO'ları İşleme (IncludeGPOs kontrolü artık kesin çalışır)
        If ($ou.LinkedGroupPolicyObjects -and $IncludeGPOs) {
            $GpoLinks = $ou.LinkedGroupPolicyObjects -split "\]\[" | Where-Object { $_ -match '{[a-zA-Z0-9]{8}[-][a-zA-Z0-9]{4}[-][a-zA-Z0-9]{4}[-][a-zA-Z0-9]{4}[-][a-zA-Z0-9]{12}}' }
            $CanonicalPath = $OUConName
            
            if ($GpoLinks.Count -gt 0) {
                if ($GroupLinkedGPOs) { 
                    Draw-GPOs-Grouped -TargetShape $shape -GpoLinks $GpoLinks -MasterGPO $MasterGPO -Connector $Connector -DNSDomain $DNSDomain -CanonicalPath $CanonicalPath
                } else {
                    Draw-GPOs-Standard -TargetShape $shape -GpoLinks $GpoLinks -MasterGPO $MasterGPO -Connector $Connector -DNSDomain $DNSDomain -CanonicalPath $CanonicalPath
                }
            }
        }
    }
}

function Format-VisioDocument {
    # Çizim tamamlandıktan sonra Visio sayfasını düzenler ve şekilleri hizalar.
    param([string]$LayoutDirection)
    Write-Host "Visio Sayfası Biçimlendiriliyor..." -ForegroundColor Cyan

    try {
        $ls = New-Object VisioAutomation.Models.LayoutStyles.hierarchyLayoutStyle
        $ls.AvenueSizeX = 1; $ls.AvenueSizeY = 1
        $ls.LayoutDirection = $LayoutDirection 
        $ls.ConnectorStyle = "Simple"; $ls.ConnectorAppearance = "Straight"
        $ls.horizontalAlignment = "Left"; $ls.verticalAlignment = "Top"

        Format-VisioPage -LayoutStyle $ls 
        Format-VisioPage -FitContents -BorderWidth 1.0 -BorderHeight 1.0
        
        # GPO bağlantılarındaki metin pozisyonunu düzeltir.
        $con_cells = New-VisioShapeCells
        $con_cells.TextFormPinX = "=POINTALONGPATH(Geometry1.Path,1)"
        $con_cells.TextFormPinY = "=POINTALONGPATH(Geometry1.Path,.75)"
        $gpoShapes = Get-VisioShape -Name * | Where-Object {$_.Nameu -like "gcon*"}
        
        ForEach($shape in $gpoShapes) {
            Set-VisioShapeCells -Cells $con_cells -Shape $shape    
        }
        Write-Host "Visio Sayfası biçimlendirildi ve belge oluşturuldu" -ForegroundColor Green
    }
    catch {
        Write-Warning "Visio sayfası biçimlendirilirken hata oluştu: $($_.Exception.Message)"
    }
}

# -----------------------------------------------------------------------------
# BÖLÜM 4: ANA YÜRÜTME FONKSİYONU 🚀
# -----------------------------------------------------------------------------

function Start-ADVisioMap {
    param([string]$LayoutDirection, 
           # KRİTİK DÜZELTME: Artık [bool]
           [bool]$IncludeGPOs, 
           [bool]$GroupLinkedGPOs, [string]$ADStencilPath,
          [switch]$IncludeObjectCounts)
    
    Import-RequiredModules
    
    $DNSDomain = $env:USERDNSDOMAIN; 
    if($null -eq $DNSDomain) { Write-Warning "DNS Alanı alınamadı"; Read-Host "Çıkmak için tuşa basın"; return }

    Write-Host "Visio Belgesi oluşturuluyor..." -ForegroundColor Cyan
    New-VisioApplication
    $VisioDoc = New-VisioDocument
    $null = $VisioDoc.Pages[1]
    
    $masters = Initialize-VisioMasters -ADStencilPath $ADStencilPath
    $ADData = Get-ADData -DNSDomain $DNSDomain -IncludeObjectCounts $IncludeObjectCounts
    
    # Kök Alan (Domain) şeklini oluştur
    Write-Host "Kök alan şekli oluşturuluyor..." -ForegroundColor Yellow
    $n0 = New-VisioShape -Master $masters.masterDomain -Position (New-VisioPoint -X 1.0 -Y 1.0) 
    $n0.Text = $DNSDomain; $n0.Name = "n" + $DNSDomain 

    # Kök alana bağlı GPO'ları çiz (IncludeGPOs kontrolü)
    if ($IncludeGPOs) {
        Draw-RootGPOs -RootDomainShape $n0 -RootGPOs $ADData.RootGPOs -MasterGPO $masters.masterGPO -Connector $masters.connector -DNSDomain $DNSDomain -GroupLinkedGPOs $GroupLinkedGPOs
    }
    
    # OU hiyerarşisini ve OU'lara bağlı GPO'ları çiz
    Draw-OUHierarchy -OUs $ADData.OUs -RootDomainShape $n0 -MasterOU $masters.masterOU -MasterGPO $masters.masterGPO -Connector $masters.connector -DNSDomain $DNSDomain -IncludeGPOs $IncludeGPOs -GroupLinkedGPOs $GroupLinkedGPOs -IncludeObjectCounts $IncludeObjectCounts
                     
    # GPO'lar gruplandırıldıysa bir rapor göster
    if ($GroupLinkedGPOs) {
        Write-Host "`n--- GPO Numaralandırma Raporu ---" -ForegroundColor Yellow
        $Script:GPOList | Select-Object Number, DisplayName, @{Name='LinkedTo'; Expression={$_.LinkedTo -join ", "}} | Format-Table -AutoSize
        Write-Host "----------------------------------" -ForegroundColor Yellow
    }
                     
    # Visio sayfasını biçimlendir ve düzenle
    Format-VisioDocument -LayoutDirection $LayoutDirection
    
    Write-Host "`nTemizlik yapılıyor..." -ForegroundColor DarkGray
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    Write-Host "`nScript tamamlandı. Visio haritanız çizildi." -ForegroundColor Green
    Read-Host "Çıkmak için herhangi bir tuşa basın."
}

# -----------------------------------------------------------------------------
# --- YÜRÜTME VE AYARLAR (LÜTFEN PARAMETRELERİ DÜZENLEYİN) ---
# -----------------------------------------------------------------------------

# Bu blok, Scripti çalıştırmak için kullanılan ayarları tanımlar.
$CustomParams = @{
    # AD ŞABLON YOLU (KRİTİK): Lütfen bu yolu kendi VSS dosyanızın TAM YOLU ile değiştirin!
    ADStencilPath   = "C:\Users\Administrator\Documents\Şekillerim\Active Directory Nesneleri.vss"; 

    # GÖRSEL VE DÜZEN AYARLARI
    # Harita düzeni yönü: "LeftToRight" (Varsayılan) veya "TopToBottom"
    LayoutDirection = "LeftToRight"; 

    # GPO AYARLARI
    # GPO'ları çizime dahil etmek için $true. ($false ise GPO çizimi yapılmaz)
    IncludeGPOs     = $true;         
    # GPO'ları gruplama (Ayrı ayrı çizmek için $false, tek bir özet şekli için $true)
    GroupLinkedGPOs = $true;        
    
    # GELİŞMİŞ VERİ AYARLARI
    # OU'ların altındaki tüm nesne (User/Computer/Group) sayılarını göster.
    IncludeObjectCounts = $true;     
}

# Tanımlı ayarlar ile Scripti başlatır
Start-ADVisioMap @CustomParams