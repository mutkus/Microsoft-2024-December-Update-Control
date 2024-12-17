#Kim: Mustafa Utku SEYITHANOGLU
#Blog: mutkus.com
#Kişisel: mutk.us
#LinkedIn: linkedin.com/in/mutkus
#GitHub: github.com/mutkus


# CVE'lere karşılık gelen KB haritaları
$CVE_49124_KBs = @{
    "windows_10-1507" = "kb5048703"
    "windows_10-1607" = "kb5048671"
    "windows_10-1809" = "kb5048661"
    "windows_10-21h2" = "kb5048652"
    "windows_10-22h2" = "kb5048652"
    "windows_11-22h2" = "kb5048685"
    "windows_11-23h2" = "kb5048685"
    "windows_11-24h2" = "kb5048667"
    "windows_server_2012" = "kb5048699"
    "windows_server_2012_r2" = "kb5048735"
    "windows_server_2016-1607" = "kb5048671"
    "windows_server_2019-1809" = "kb5048661"
    "windows_server_2022-21h2" = "kb5048654"
    "windows_server_2022-22h2" = "kb5048654"
    "windows_server_2022-23h2" = "kb5048653"
    "windows_server_2025-24h2" = "kb5048667"
}

$CVE_49117_KBs = @{
    "windows_11-22h2" = "kb5048685"
    "windows_11-23h2" = "kb5048685"
    "windows_11-24h2" = "kb5048667"
    "windows_server_2022-21h2" = "kb5048654"
    "windows_server_2022-22h2" = "kb5048654"
    "windows_server_2022-23h2" = "kb5048653"
    "windows_server_2025-24h2" = "kb5048667"
}

$CVE_49122_KBs = @{
    "windows_10-1507" = "kb5048703"
    "windows_10-1607" = "kb5048671"
    "windows_10-1809" = "kb5048661"
    "windows_10-21h2" = "kb5048652"
    "windows_10-22h2" = "kb5048652"
    "windows_11-22h2" = "kb5048685"
    "windows_11-23h2" = "kb5048685"
    "windows_11-24h2" = "kb5048667"
    "windows_server_2012" = "kb5048699"
    "windows_server_2012_r2" = "kb5048735"
    "windows_server_2016-1607" = "kb5048671"
    "windows_server_2019-1809" = "kb5048661"
    "windows_server_2022-21h2" = "kb5048654"
    "windows_server_2022-22h2" = "kb5048654"
    "windows_server_2022-23h2" = "kb5048653"
    "windows_server_2025-24h2" = "kb5048667"
}

$CVE_49118_KBs = @{
    "windows_10-1507" = "kb5048703"
    "windows_10-1607" = "kb5048671"
    "windows_10-1809" = "kb5048661"
    "windows_10-21h2" = "kb5048652"
    "windows_10-22h2" = "kb5048652"
    "windows_11-22h2" = "kb5048685"
    "windows_11-23h2" = "kb5048685"
    "windows_11-24h2" = "kb5048667"
    "windows_server_2012" = "kb5048699"
    "windows_server_2012_r2" = "kb5048735"
    "windows_server_2016-1607" = "kb5048671"
    "windows_server_2019-1809" = "kb5048661"
    "windows_server_2022-21h2" = "kb5048654"
    "windows_server_2022-22h2" = "kb5048654"
    "windows_server_2022-23h2" = "kb5048653"
    "windows_server_2025-24h2" = "kb5048667"
}

$CVE_Map = @{
    "CVE-2024-49124" = $CVE_49124_KBs
    "CVE-2024-49117" = $CVE_49117_KBs
    "CVE-2024-49122" = $CVE_49122_KBs
    "CVE-2024-49118" = $CVE_49118_KBs
}

# İşletim Sistemi Tespiti
$OSInfo = Get-CimInstance Win32_OperatingSystem
Write-Host "Tespit edilen işletim sistemi: $($OSInfo.Caption) $($OSInfo.Version)"

function Get-OSKey {
    param($Caption, $Version)
    $cap = $Caption.ToLower()

    if ($cap -match "windows 10") {
        if ([version]$Version -lt [version]"10.0.10500") {
            return "windows_10-1507"
        } elseif ([version]$Version -ge [version]"10.0.14393" -and [version]$Version -lt [version]"10.0.14400") {
            return "windows_10-1607"
        } elseif ([version]$Version -ge [version]"10.0.17763" -and [version]$Version -lt [version]"10.0.17764") {
            return "windows_10-1809"
        } elseif ([version]$Version -ge [version]"10.0.19044" -and [version]$Version -lt [version]"10.0.19045") {
            return "windows_10-21h2"
        } elseif ([version]$Version -ge [version]"10.0.19045" -and [version]$Version -lt [version]"10.0.19046") {
            return "windows_10-22h2"
        } else {
            return $null
        }
    } elseif ($cap -match "windows 11") {
        # Burada örnek olarak belirli sürümler varsayılmıştır.
        if ([version]$Version -ge [version]"10.0.22621" -and [version]$Version -lt [version]"10.0.22622") {
            return "windows_11-22h2"
        } elseif ([version]$Version -ge [version]"10.0.22631" -and [version]$Version -lt [version]"10.0.22632") {
            return "windows_11-23h2"
        } elseif ([version]$Version -ge [version]"10.0.22641" -and [version]$Version -lt [version]"10.0.22642") {
            return "windows_11-24h2"
        } else {
            return $null
        }
    } elseif ($cap -match "windows server") {
        if ($cap -match "2012 r2") {
            return "windows_server_2012_r2"
        } elseif ($cap -match "2012") {
            return "windows_server_2012"
        } elseif ($cap -match "2016") {
            return "windows_server_2016-1607"
        } elseif ($cap -match "2019") {
            return "windows_server_2019-1809"
        } elseif ($cap -match "2022") {
            # Bu kısım tamamen örnektir.
            if ([version]$Version -ge [version]"10.0.20348" -and [version]$Version -lt [version]"10.0.20349") {
                return "windows_server_2022-21h2"
            } elseif ([version]$Version -ge [version]"10.0.20349" -and [version]$Version -lt [version]"10.0.20350") {
                return "windows_server_2022-22h2"
            } elseif ([version]$Version -ge [version]"10.0.20351" -and [version]$Version -lt [version]"10.0.20352") {
                return "windows_server_2022-23h2"
            } else {
                return $null
            }
        } elseif ($cap -match "2025") {
            return "windows_server_2025-24h2"
        } else {
            return $null
        }
    } else {
        return $null
    }
}

$OSKey = Get-OSKey -Caption $OSInfo.Caption -Version $OSInfo.Version

Write-Host "Güncellemeler kontrol ediliyor..."
$InstalledUpdates = Get-HotFix

foreach ($CVE in $CVE_Map.Keys) {
    $KBMap = $CVE_Map[$CVE]
    $requiredKB = $null

    if ($OSKey -and $KBMap.ContainsKey($OSKey)) {
        $requiredKB = $KBMap[$OSKey]
    } else {
        Write-Host "$CVE için tam OS sürüm eşleşmesi bulunamadı, listedeki KB'lere bakılıyor..." -ForegroundColor Yellow
    }

    if ($requiredKB) {
        $isInstalled = $InstalledUpdates | Where-Object { $_.HotFixID -eq $requiredKB }
        if ($isInstalled) {
            Write-Host "$CVE gideren $requiredKB güncelleştirmesi SİSTEMDE YÜKLÜ." -ForegroundColor Green
        } else {
            Write-Host "$CVE gideren $requiredKB güncelleştirmesi SİSTEMDE BULUNMUYOR!" -ForegroundColor Red
        }
    } else {
        # Eğer OSKey bulunamadıysa, listedeki herhangi bir KB var mı kontrol et.
        $allKBs = $KBMap.Values
        $installedAny = $false
        foreach ($kbItem in $allKBs) {
            $found = $InstalledUpdates | Where-Object { $_.HotFixID -eq $kbItem }
            if ($found) {
                Write-Host "$CVE için $kbItem yüklü. Bu CVE muhtemelen giderilmiş." -ForegroundColor Green
                $installedAny = $true
                break
            }
        }
        if (-not $installedAny) {
            Write-Host "$CVE için listelenen yamalardan hiçbiri bulunamadı." -ForegroundColor Red
        }
    }
}

Write-Host "Kontrol tamamlandı."
