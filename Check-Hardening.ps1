<#
.SYNOPSIS
    Überprüft die Windows-Härtung und erstellt einen Status-Report
    
.DESCRIPTION
    Dieses Script überprüft die wichtigsten Sicherheitseinstellungen und
    erstellt einen detaillierten Report über den Härtungsstatus.
    
.PARAMETER ExportPath
    Pfad für den Export des HTML-Reports (optional)
    
.EXAMPLE
    .\Check-Hardening.ps1
    
.EXAMPLE
    .\Check-Hardening.ps1 -ExportPath "C:\Reports\Hardening-Status.html"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath
)

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$ExpectedValue
    )
    
    try {
        if (-not (Test-Path $Path)) {
            return @{
                Status = 'NotSet'
                Current = $null
                Expected = $ExpectedValue
            }
        }
        
        $currentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name
        
        if ($null -eq $currentValue) {
            return @{
                Status = 'NotSet'
                Current = $null
                Expected = $ExpectedValue
            }
        }
        
        if ($currentValue -eq $ExpectedValue) {
            return @{
                Status = 'OK'
                Current = $currentValue
                Expected = $ExpectedValue
            }
        }
        else {
            return @{
                Status = 'Different'
                Current = $currentValue
                Expected = $ExpectedValue
            }
        }
    }
    catch {
        return @{
            Status = 'Error'
            Current = $null
            Expected = $ExpectedValue
            Error = $_.Exception.Message
        }
    }
}

Write-Host "`n=====================================================================" -ForegroundColor Cyan
Write-Host "  Windows 11 Härtungs-Überprüfung" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

$results = @()

# System-Information
Write-Host "`n[*] Sammle System-Informationen..." -ForegroundColor Yellow
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$compInfo = Get-ComputerInfo

$systemInfo = @{
    ComputerName = $env:COMPUTERNAME
    OSVersion = $osInfo.Caption
    BuildNumber = $osInfo.BuildNumber
    InstallDate = $osInfo.InstallDate
    LastBootUpTime = $osInfo.LastBootUpTime
}

# ============================================================================
# 1. Device Guard / Credential Guard
# ============================================================================

Write-Host "[1/10] Überprüfe Device Guard..." -ForegroundColor Yellow

$checks = @(
    @{
        Category = "Device Guard"
        Name = "LSA Protection (Credential Guard)"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        Setting = "LsaCfgFlags"
        Expected = 2
    },
    @{
        Category = "Device Guard"
        Name = "Virtualization Based Security"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        Setting = "EnableVirtualizationBasedSecurity"
        Expected = 1
    },
    @{
        Category = "Device Guard"
        Name = "HVCI (Hypervisor Code Integrity)"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        Setting = "HypervisorEnforcedCodeIntegrity"
        Expected = 1
    }
)

foreach ($check in $checks) {
    $result = Test-RegistryValue -Path $check.Path -Name $check.Setting -ExpectedValue $check.Expected
    $results += [PSCustomObject]@{
        Category = $check.Category
        Check = $check.Name
        Status = $result.Status
        Current = $result.Current
        Expected = $result.Expected
    }
}

# ============================================================================
# 2. Windows Defender
# ============================================================================

Write-Host "[2/10] Überprüfe Windows Defender..." -ForegroundColor Yellow

try {
    $defenderStatus = Get-MpComputerStatus
    
    $results += [PSCustomObject]@{
        Category = "Windows Defender"
        Check = "Echtzeit-Schutz"
        Status = if ($defenderStatus.RealTimeProtectionEnabled) { 'OK' } else { 'Different' }
        Current = $defenderStatus.RealTimeProtectionEnabled
        Expected = $true
    }
    
    $results += [PSCustomObject]@{
        Category = "Windows Defender"
        Check = "Cloud-Schutz"
        Status = if ($defenderStatus.MAPSReporting -ge 1) { 'OK' } else { 'Different' }
        Current = $defenderStatus.MAPSReporting
        Expected = "1 oder höher"
    }
    
    $results += [PSCustomObject]@{
        Category = "Windows Defender"
        Check = "Verhalten-Monitoring"
        Status = if ($defenderStatus.BehaviorMonitorEnabled) { 'OK' } else { 'Different' }
        Current = $defenderStatus.BehaviorMonitorEnabled
        Expected = $true
    }
}
catch {
    $results += [PSCustomObject]@{
        Category = "Windows Defender"
        Check = "Status-Abfrage"
        Status = 'Error'
        Current = "Fehler"
        Expected = "Aktiv"
    }
}

# ============================================================================
# 3. PowerShell Logging
# ============================================================================

Write-Host "[3/10] Überprüfe PowerShell Logging..." -ForegroundColor Yellow

$psChecks = @(
    @{
        Name = "Script Block Logging"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        Setting = "EnableScriptBlockLogging"
        Expected = 1
    },
    @{
        Name = "Module Logging"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        Setting = "EnableModuleLogging"
        Expected = 1
    },
    @{
        Name = "Transcription"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        Setting = "EnableTranscripting"
        Expected = 1
    }
)

foreach ($check in $psChecks) {
    $result = Test-RegistryValue -Path $check.Path -Name $check.Setting -ExpectedValue $check.Expected
    $results += [PSCustomObject]@{
        Category = "PowerShell Security"
        Check = $check.Name
        Status = $result.Status
        Current = $result.Current
        Expected = $result.Expected
    }
}

# ============================================================================
# 4. User Account Control
# ============================================================================

Write-Host "[4/10] Überprüfe User Account Control..." -ForegroundColor Yellow

$uacChecks = @(
    @{
        Name = "UAC aktiviert"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Setting = "EnableLUA"
        Expected = 1
    },
    @{
        Name = "UAC auf sicherem Desktop"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Setting = "PromptOnSecureDesktop"
        Expected = 1
    },
    @{
        Name = "Admin-Zustimmungsaufforderung"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Setting = "ConsentPromptBehaviorAdmin"
        Expected = 2
    }
)

foreach ($check in $uacChecks) {
    $result = Test-RegistryValue -Path $check.Path -Name $check.Setting -ExpectedValue $check.Expected
    $results += [PSCustomObject]@{
        Category = "User Account Control"
        Check = $check.Name
        Status = $result.Status
        Current = $result.Current
        Expected = $result.Expected
    }
}

# ============================================================================
# 5. Netzwerk-Sicherheit
# ============================================================================

Write-Host "[5/10] Überprüfe Netzwerk-Sicherheit..." -ForegroundColor Yellow

# SMBv1
try {
    $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    $results += [PSCustomObject]@{
        Category = "Netzwerk"
        Check = "SMBv1 deaktiviert"
        Status = if ($smbv1.State -eq "Disabled") { 'OK' } else { 'Different' }
        Current = $smbv1.State
        Expected = "Disabled"
    }
}
catch {
    $results += [PSCustomObject]@{
        Category = "Netzwerk"
        Check = "SMBv1 Status"
        Status = 'Error'
        Current = "Nicht prüfbar"
        Expected = "Disabled"
    }
}

# SMB Signing
$netChecks = @(
    @{
        Name = "SMB Server Signing"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Setting = "RequireSecuritySignature"
        Expected = 1
    },
    @{
        Name = "SMB Client Signing"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        Setting = "RequireSecuritySignature"
        Expected = 1
    },
    @{
        Name = "LLMNR deaktiviert"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        Setting = "EnableMulticast"
        Expected = 0
    }
)

foreach ($check in $netChecks) {
    $result = Test-RegistryValue -Path $check.Path -Name $check.Setting -ExpectedValue $check.Expected
    $results += [PSCustomObject]@{
        Category = "Netzwerk"
        Check = $check.Name
        Status = $result.Status
        Current = $result.Current
        Expected = $result.Expected
    }
}

# ============================================================================
# 6. Remote Desktop
# ============================================================================

Write-Host "[6/10] Überprüfe Remote Desktop..." -ForegroundColor Yellow

$rdpChecks = @(
    @{
        Name = "RDP NLA (Network Level Auth)"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        Setting = "UserAuthentication"
        Expected = 1
    },
    @{
        Name = "RDP Verschlüsselungsstufe"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        Setting = "MinEncryptionLevel"
        Expected = 3
    }
)

foreach ($check in $rdpChecks) {
    $result = Test-RegistryValue -Path $check.Path -Name $check.Setting -ExpectedValue $check.Expected
    $results += [PSCustomObject]@{
        Category = "Remote Desktop"
        Check = $check.Name
        Status = $result.Status
        Current = $result.Current
        Expected = $result.Expected
    }
}

# ============================================================================
# 7. Anmelde-Richtlinien
# ============================================================================

Write-Host "[7/10] Überprüfe Anmelde-Richtlinien..." -ForegroundColor Yellow

try {
    $secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet
    $secpolContent = Get-Content "$env:TEMP\secpol.cfg"
    Remove-Item "$env:TEMP\secpol.cfg" -Force
    
    # Lockout Threshold
    $lockoutLine = $secpolContent | Where-Object { $_ -like "LockoutBadCount*" }
    if ($lockoutLine -match "= (\d+)") {
        $lockoutCount = [int]$matches[1]
        $results += [PSCustomObject]@{
            Category = "Anmelde-Richtlinien"
            Check = "Konto-Sperrung (Fehlversuche)"
            Status = if ($lockoutCount -ge 3 -and $lockoutCount -le 10) { 'OK' } else { 'Different' }
            Current = $lockoutCount
            Expected = "3-10"
        }
    }
    
    # Minimale Passwortlänge
    $pwdLine = $secpolContent | Where-Object { $_ -like "MinimumPasswordLength*" }
    if ($pwdLine -match "= (\d+)") {
        $minPwdLen = [int]$matches[1]
        $results += [PSCustomObject]@{
            Category = "Anmelde-Richtlinien"
            Check = "Minimale Passwortlänge"
            Status = if ($minPwdLen -ge 12) { 'OK' } else { 'Different' }
            Current = $minPwdLen
            Expected = "≥12"
        }
    }
}
catch {
    $results += [PSCustomObject]@{
        Category = "Anmelde-Richtlinien"
        Check = "Richtlinien-Export"
        Status = 'Error'
        Current = "Fehler beim Export"
        Expected = "Erfolgreich"
    }
}

# ============================================================================
# 8. Zusätzliche Sicherheitseinstellungen
# ============================================================================

Write-Host "[8/10] Überprüfe zusätzliche Einstellungen..." -ForegroundColor Yellow

$miscChecks = @(
    @{
        Name = "AutoRun deaktiviert"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Setting = "NoDriveTypeAutoRun"
        Expected = 255
    },
    @{
        Name = "Anonyme SAM-Aufzählung verhindert"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Setting = "RestrictAnonymousSAM"
        Expected = 1
    },
    @{
        Name = "NTLMv2 erzwungen"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Setting = "LmCompatibilityLevel"
        Expected = 5
    }
)

foreach ($check in $miscChecks) {
    $result = Test-RegistryValue -Path $check.Path -Name $check.Setting -ExpectedValue $check.Expected
    $results += [PSCustomObject]@{
        Category = "Zusätzliche Sicherheit"
        Check = $check.Name
        Status = $result.Status
        Current = $result.Current
        Expected = $result.Expected
    }
}

# ============================================================================
# 9. BitLocker Status (optional)
# ============================================================================

Write-Host "[9/10] Überprüfe BitLocker..." -ForegroundColor Yellow

try {
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($bitlockerVolumes) {
        foreach ($vol in $bitlockerVolumes | Where-Object { $_.VolumeType -eq 'OperatingSystem' }) {
            $results += [PSCustomObject]@{
                Category = "Verschlüsselung"
                Check = "BitLocker auf $($vol.MountPoint)"
                Status = if ($vol.ProtectionStatus -eq 'On') { 'OK' } else { 'Different' }
                Current = $vol.ProtectionStatus
                Expected = "On"
            }
        }
    }
}
catch {
    $results += [PSCustomObject]@{
        Category = "Verschlüsselung"
        Check = "BitLocker"
        Status = 'NotSet'
        Current = "Nicht verfügbar oder nicht konfiguriert"
        Expected = "Aktiviert"
    }
}

# ============================================================================
# 10. Windows Update
# ============================================================================

Write-Host "[10/10] Überprüfe Windows Update..." -ForegroundColor Yellow

try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $pendingUpdates = $updateSearcher.Search("IsInstalled=0 and Type='Software'").Updates
    
    $results += [PSCustomObject]@{
        Category = "Windows Update"
        Check = "Ausstehende Updates"
        Status = if ($pendingUpdates.Count -eq 0) { 'OK' } else { 'Different' }
        Current = "$($pendingUpdates.Count) ausstehend"
        Expected = "0"
    }
}
catch {
    $results += [PSCustomObject]@{
        Category = "Windows Update"
        Check = "Update-Status"
        Status = 'Error'
        Current = "Nicht prüfbar"
        Expected = "Aktuell"
    }
}

# ============================================================================
# Ergebnisse anzeigen
# ============================================================================

Write-Host "`n=====================================================================" -ForegroundColor Cyan
Write-Host "  Überprüfungsergebnisse" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

$okCount = ($results | Where-Object { $_.Status -eq 'OK' }).Count
$differentCount = ($results | Where-Object { $_.Status -eq 'Different' }).Count
$notSetCount = ($results | Where-Object { $_.Status -eq 'NotSet' }).Count
$errorCount = ($results | Where-Object { $_.Status -eq 'Error' }).Count
$totalCount = $results.Count

Write-Host "`nZusammenfassung:" -ForegroundColor White
Write-Host "  ✓ OK:              " -NoNewline -ForegroundColor Green
Write-Host "$okCount / $totalCount"
Write-Host "  ! Abweichend:      " -NoNewline -ForegroundColor Yellow
Write-Host "$differentCount / $totalCount"
Write-Host "  ○ Nicht gesetzt:   " -NoNewline -ForegroundColor Gray
Write-Host "$notSetCount / $totalCount"
Write-Host "  ✗ Fehler:          " -NoNewline -ForegroundColor Red
Write-Host "$errorCount / $totalCount"

# Gruppiert nach Kategorie anzeigen
Write-Host "`nDetails nach Kategorie:" -ForegroundColor White
$results | Group-Object Category | ForEach-Object {
    Write-Host "`n$($_.Name):" -ForegroundColor Cyan
    $_.Group | ForEach-Object {
        $symbol = switch ($_.Status) {
            'OK'        { '✓' ; $color = 'Green' }
            'Different' { '!' ; $color = 'Yellow' }
            'NotSet'    { '○' ; $color = 'Gray' }
            'Error'     { '✗' ; $color = 'Red' }
        }
        Write-Host "  $symbol " -NoNewline -ForegroundColor $color
        Write-Host "$($_.Check): " -NoNewline
        Write-Host "Ist=$($_.Current), " -NoNewline -ForegroundColor $color
        Write-Host "Soll=$($_.Expected)" -ForegroundColor Gray
    }
}

# HTML-Export (optional)
if ($ExportPath) {
    Write-Host "`nErstelle HTML-Report..." -ForegroundColor Yellow
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Windows Härtungs-Report - $($systemInfo.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #0078d4; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .category { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .category h3 { margin-top: 0; color: #0078d4; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f0f0f0; text-align: left; padding: 10px; border-bottom: 2px solid #ddd; }
        td { padding: 10px; border-bottom: 1px solid #eee; }
        .status-ok { color: #107c10; font-weight: bold; }
        .status-different { color: #ff8c00; font-weight: bold; }
        .status-notset { color: #999; }
        .status-error { color: #d13438; font-weight: bold; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 2em; font-weight: bold; }
        .metric-label { color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Windows Härtungs-Report</h1>
        <p>Computer: $($systemInfo.ComputerName) | $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')</p>
        <p>$($systemInfo.OSVersion) (Build $($systemInfo.BuildNumber))</p>
    </div>
    
    <div class="summary">
        <h2>Zusammenfassung</h2>
        <div class="metric">
            <div class="metric-value status-ok">$okCount</div>
            <div class="metric-label">OK</div>
        </div>
        <div class="metric">
            <div class="metric-value status-different">$differentCount</div>
            <div class="metric-label">Abweichend</div>
        </div>
        <div class="metric">
            <div class="metric-value status-notset">$notSetCount</div>
            <div class="metric-label">Nicht gesetzt</div>
        </div>
        <div class="metric">
            <div class="metric-value status-error">$errorCount</div>
            <div class="metric-label">Fehler</div>
        </div>
    </div>
"@

    # Gruppierte Ergebnisse
    $results | Group-Object Category | ForEach-Object {
        $html += @"
    <div class="category">
        <h3>$($_.Name)</h3>
        <table>
            <tr>
                <th>Status</th>
                <th>Prüfung</th>
                <th>Aktuell</th>
                <th>Erwartet</th>
            </tr>
"@
        $_.Group | ForEach-Object {
            $statusClass = "status-$($_.Status.ToLower())"
            $statusSymbol = switch ($_.Status) {
                'OK'        { '✓' }
                'Different' { '!' }
                'NotSet'    { '○' }
                'Error'     { '✗' }
            }
            
            $html += @"
            <tr>
                <td class="$statusClass">$statusSymbol $($_.Status)</td>
                <td>$($_.Check)</td>
                <td>$($_.Current)</td>
                <td>$($_.Expected)</td>
            </tr>
"@
        }
        $html += @"
        </table>
    </div>
"@
    }
    
    $html += @"
</body>
</html>
"@

    $html | Out-File -FilePath $ExportPath -Encoding UTF8
    Write-Host "HTML-Report erstellt: $ExportPath" -ForegroundColor Green
}

Write-Host "`n=====================================================================" -ForegroundColor Cyan
Write-Host "Überprüfung abgeschlossen!" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan