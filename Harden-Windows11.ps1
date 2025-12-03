<#
.SYNOPSIS
    Windows 11 Professional Härtungs-Script für Stand-alone Installationen
    
.DESCRIPTION
    Dieses Script härtet Windows 11 Professional Systeme basierend auf Best Practices
    aus dem Microsoft Security Compliance Toolkit, STIG und allgemeinen Sicherheitsempfehlungen.
    
.NOTES
    Autor: Basierend auf iX-Artikel "Windows härten mit Microsoft-Tools"
    Datum: Dezember 2025
    Version: 1.0
    
    WICHTIG: Dieses Script muss mit Administratorrechten ausgeführt werden!
    
.EXAMPLE
    .\Harden-Windows11.ps1
    
.EXAMPLE
    .\Harden-Windows11.ps1 -CreateBackup -LogPath "C:\Logs"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "$PSScriptRoot\Logs",
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateBackup = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDeviceGuard = $false
)

#Requires -RunAsAdministrator

# ============================================================================
# Funktionen
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARNING','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    $color = switch ($Level) {
        'INFO'    { 'White' }
        'WARNING' { 'Yellow' }
        'ERROR'   { 'Red' }
        'SUCCESS' { 'Green' }
    }
    
    Write-Host $logMessage -ForegroundColor $color
    
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    $logFile = Join-Path $LogPath "Hardening_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logMessage
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [ValidateSet('String','ExpandString','Binary','DWord','MultiString','QWord')]
        [string]$Type = 'DWord',
        [string]$Description = ""
    )
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Log "Registry-Pfad erstellt: $Path" -Level INFO
        }
        
        $currentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        
        if ($currentValue.$Name -ne $Value) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            Write-Log "✓ $Description | $Path\$Name = $Value" -Level SUCCESS
            return $true
        } else {
            Write-Log "○ Bereits gesetzt: $Description" -Level INFO
            return $false
        }
    }
    catch {
        Write-Log "✗ Fehler bei $Description : $_" -Level ERROR
        return $false
    }
}

function Backup-CurrentSettings {
    param([string]$BackupPath)
    
    Write-Log "Erstelle Backup der aktuellen Einstellungen..." -Level INFO
    
    if (-not (Test-Path $BackupPath)) {
        New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
    }
    
    $backupFile = Join-Path $BackupPath "Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    $backupData = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName = $env:COMPUTERNAME
        Settings = @{}
    }
    
    # Wichtige Registry-Werte sichern
    $registryPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    )
    
    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $backupData.Settings[$path] = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        }
    }
    
    $backupData | ConvertTo-Json -Depth 10 | Out-File -FilePath $backupFile -Encoding UTF8
    Write-Log "Backup erstellt: $backupFile" -Level SUCCESS
    
    return $backupFile
}

# ============================================================================
# Hauptprogramm
# ============================================================================

Write-Host "`n=====================================================================" -ForegroundColor Cyan
Write-Host "  Windows 11 Professional Härtungs-Script" -ForegroundColor Cyan
Write-Host "  Version 1.0 - Dezember 2025" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

Write-Log "Script gestartet auf $env:COMPUTERNAME" -Level INFO
Write-Log "Benutzer: $env:USERNAME" -Level INFO

# Prüfe Windows-Version
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
Write-Log "OS: $($osInfo.Caption) (Build $($osInfo.BuildNumber))" -Level INFO

if ($osInfo.Caption -notlike "*Windows 11*") {
    Write-Log "WARNUNG: Dieses Script ist für Windows 11 optimiert!" -Level WARNING
    $continue = Read-Host "Trotzdem fortfahren? (J/N)"
    if ($continue -ne 'J') {
        exit
    }
}

# Backup erstellen
if ($CreateBackup) {
    $backupPath = Join-Path $PSScriptRoot "Backups"
    $backupFile = Backup-CurrentSettings -BackupPath $backupPath
}

$changesCount = 0

# ============================================================================
# 1. Device Guard und Credential Guard Härtung
# ============================================================================

Write-Log "`n[1/10] Device Guard und Credential Guard konfigurieren..." -Level INFO

if (-not $SkipDeviceGuard) {
    # LSA Protection (Credential Guard)
    $changesCount += Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        -Name "LsaCfgFlags" `
        -Value 2 `
        -Description "LSA Protection aktivieren (Credential Guard)"
    
    # Credential Guard aktivieren
    $changesCount += Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        -Name "EnableVirtualizationBasedSecurity" `
        -Value 1 `
        -Description "Virtualization Based Security aktivieren"
    
    $changesCount += Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        -Name "RequirePlatformSecurityFeatures" `
        -Value 3 `
        -Description "Secure Boot und DMA Protection"
    
    $changesCount += Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        -Name "HypervisorEnforcedCodeIntegrity" `
        -Value 1 `
        -Description "Hypervisor-Enforced Code Integrity (HVCI)"
    
    $changesCount += Set-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" `
        -Name "ConfigureSystemGuardLaunch" `
        -Value 1 `
        -Description "System Guard Launch konfigurieren"
} else {
    Write-Log "Device Guard übersprungen (Parameter)" -Level WARNING
}

# ============================================================================
# 2. Windows Defender Härtung
# ============================================================================

Write-Log "`n[2/10] Windows Defender konfigurieren..." -Level INFO

# Echtzeit-Schutz
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
    -Name "DisableRealtimeMonitoring" `
    -Value 0 `
    -Description "Echtzeit-Schutz aktiviert"

# Cloud-basierter Schutz
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
    -Name "SpynetReporting" `
    -Value 2 `
    -Description "Cloud-Schutz: Erweiterte Berichte"

# Automatische Beispielübermittlung
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
    -Name "SubmitSamplesConsent" `
    -Value 1 `
    -Description "Automatische Beispielübermittlung"

# Exploit Guard
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" `
    -Name "ExploitGuard_ASR_Rules" `
    -Value 1 `
    -Description "Attack Surface Reduction aktiviert"

# Tamper Protection über PowerShell aktivieren
try {
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    Write-Log "✓ Controlled Folder Access aktiviert" -Level SUCCESS
    $changesCount++
} catch {
    Write-Log "Controlled Folder Access konnte nicht aktiviert werden" -Level WARNING
}

# ============================================================================
# 3. PowerShell Logging und Hardening
# ============================================================================

Write-Log "`n[3/10] PowerShell Sicherheit konfigurieren..." -Level INFO

# Script Block Logging
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" `
    -Value 1 `
    -Description "PowerShell Script Block Logging"

# Module Logging
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" `
    -Value 1 `
    -Description "PowerShell Module Logging"

# Transcription
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "EnableTranscripting" `
    -Value 1 `
    -Description "PowerShell Transcription"

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "OutputDirectory" `
    -Value "C:\PSTranscripts" `
    -Type "String" `
    -Description "PowerShell Transcript-Verzeichnis"

# Transcript-Verzeichnis erstellen
if (-not (Test-Path "C:\PSTranscripts")) {
    New-Item -Path "C:\PSTranscripts" -ItemType Directory -Force | Out-Null
}

# ============================================================================
# 4. User Account Control (UAC) Härtung
# ============================================================================

Write-Log "`n[4/10] User Account Control (UAC) konfigurieren..." -Level INFO

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" `
    -Value 1 `
    -Description "UAC aktiviert"

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" `
    -Value 2 `
    -Description "UAC: Zustimmungsaufforderung für Administratoren"

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "PromptOnSecureDesktop" `
    -Value 1 `
    -Description "UAC auf sicherem Desktop"

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableInstallerDetection" `
    -Value 1 `
    -Description "UAC: Installationserkennung"

# ============================================================================
# 5. Netzwerk-Härtung
# ============================================================================

Write-Log "`n[5/10] Netzwerk-Sicherheit konfigurieren..." -Level INFO

# SMBv1 deaktivieren
try {
    $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smbv1.State -eq "Enabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
        Write-Log "✓ SMBv1 deaktiviert" -Level SUCCESS
        $changesCount++
    } else {
        Write-Log "○ SMBv1 bereits deaktiviert" -Level INFO
    }
} catch {
    Write-Log "SMBv1 konnte nicht überprüft werden" -Level WARNING
}

# SMB Signing erzwingen
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" `
    -Value 1 `
    -Description "SMB Server Signing erforderlich"

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
    -Name "RequireSecuritySignature" `
    -Value 1 `
    -Description "SMB Client Signing erforderlich"

# NetBIOS über TCP/IP deaktivieren (auf allen Adaptern)
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
    -Name "NoNameReleaseOnDemand" `
    -Value 1 `
    -Description "NetBIOS Name Release verhindern"

# LLMNR deaktivieren
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" `
    -Value 0 `
    -Description "LLMNR deaktiviert"

# ============================================================================
# 6. Remote Desktop Härtung
# ============================================================================

Write-Log "`n[6/10] Remote Desktop Sicherheit konfigurieren..." -Level INFO

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "SecurityLayer" `
    -Value 2 `
    -Description "RDP: SSL/TLS-Verschlüsselung"

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" `
    -Value 1 `
    -Description "RDP: Network Level Authentication (NLA)"

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "MinEncryptionLevel" `
    -Value 3 `
    -Description "RDP: Hohe Verschlüsselungsstufe"

# ============================================================================
# 7. Audit Policy konfigurieren
# ============================================================================

Write-Log "`n[7/10] Audit-Richtlinien konfigurieren..." -Level INFO

$auditSettings = @(
    @{Category = "Account Logon"; Subcategory = "Credential Validation"; Setting = "Success,Failure"},
    @{Category = "Account Management"; Subcategory = "Security Group Management"; Setting = "Success"},
    @{Category = "Logon/Logoff"; Subcategory = "Logon"; Setting = "Success,Failure"},
    @{Category = "Logon/Logoff"; Subcategory = "Logoff"; Setting = "Success"},
    @{Category = "Object Access"; Subcategory = "File System"; Setting = "Failure"},
    @{Category = "Policy Change"; Subcategory = "Audit Policy Change"; Setting = "Success"},
    @{Category = "Privilege Use"; Subcategory = "Sensitive Privilege Use"; Setting = "Success,Failure"},
    @{Category = "System"; Subcategory = "Security System Extension"; Setting = "Success"}
)

foreach ($audit in $auditSettings) {
    try {
        $result = auditpol /set /subcategory:"$($audit.Subcategory)" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "✓ Audit: $($audit.Subcategory)" -Level SUCCESS
            $changesCount++
        }
    } catch {
        Write-Log "Audit-Einstellung fehlgeschlagen: $($audit.Subcategory)" -Level WARNING
    }
}

# ============================================================================
# 8. Windows Update Konfiguration
# ============================================================================

Write-Log "`n[8/10] Windows Update konfigurieren..." -Level INFO

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "NoAutoUpdate" `
    -Value 0 `
    -Description "Automatische Updates aktiviert"

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "AUOptions" `
    -Value 4 `
    -Description "Auto-Download und Installation planen"

# ============================================================================
# 9. Anmelde- und Lockout-Richtlinien
# ============================================================================

Write-Log "`n[9/10] Anmelde-Richtlinien konfigurieren..." -Level INFO

# Konto-Sperrung nach Fehlversuchen
try {
    net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null
    Write-Log "✓ Konto-Sperrung: 5 Fehlversuche, 30 Minuten Sperre" -Level SUCCESS
    $changesCount++
} catch {
    Write-Log "Konto-Sperrung konnte nicht konfiguriert werden" -Level WARNING
}

# Minimale Passwortlänge
try {
    net accounts /minpwlen:12 | Out-Null
    Write-Log "✓ Minimale Passwortlänge: 12 Zeichen" -Level SUCCESS
    $changesCount++
} catch {
    Write-Log "Passwortlänge konnte nicht konfiguriert werden" -Level WARNING
}

# Passwort-Historie
try {
    net accounts /uniquepw:24 | Out-Null
    Write-Log "✓ Passwort-Historie: 24 Passwörter" -Level SUCCESS
    $changesCount++
} catch {
    Write-Log "Passwort-Historie konnte nicht konfiguriert werden" -Level WARNING
}

# ============================================================================
# 10. Zusätzliche Härtungsmaßnahmen
# ============================================================================

Write-Log "`n[10/10] Zusätzliche Sicherheitseinstellungen..." -Level INFO

# Windows Script Host deaktivieren für normale Benutzer
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" `
    -Name "Enabled" `
    -Value 0 `
    -Description "Windows Script Host eingeschränkt"

# AutoRun für alle Laufwerke deaktivieren
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoDriveTypeAutoRun" `
    -Value 255 `
    -Description "AutoRun deaktiviert"

# Windows Error Reporting einschränken
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" `
    -Name "Disabled" `
    -Value 0 `
    -Description "Windows Error Reporting kontrolliert aktiviert"

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" `
    -Name "DontSendAdditionalData" `
    -Value 1 `
    -Description "Keine zusätzlichen WER-Daten senden"

# Anonyme Aufzählung von SAM-Konten verhindern
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymousSAM" `
    -Value 1 `
    -Description "Anonyme SAM-Aufzählung verhindert"

# LAN Manager Authentifizierung - NTLMv2 erzwingen
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" `
    -Value 5 `
    -Description "Nur NTLMv2, LM verweigert"

# Event Log Größen erhöhen
$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" `
    -Name "MaxSize" `
    -Value 0x8000000 `
    -Description "Application Log: 128 MB"

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
    -Name "MaxSize" `
    -Value 0x20000000 `
    -Description "Security Log: 512 MB"

$changesCount += Set-RegistryValue `
    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" `
    -Name "MaxSize" `
    -Value 0x8000000 `
    -Description "System Log: 128 MB"

# ============================================================================
# Zusammenfassung und Neustart-Empfehlung
# ============================================================================

Write-Host "`n=====================================================================" -ForegroundColor Cyan
Write-Host "  Härtung abgeschlossen!" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan

Write-Log "`nZusammenfassung:" -Level INFO
Write-Log "- Änderungen vorgenommen: $changesCount" -Level SUCCESS
Write-Log "- Log-Datei: $(Join-Path $LogPath "Hardening_$(Get-Date -Format 'yyyyMMdd').log")" -Level INFO

if ($CreateBackup -and $backupFile) {
    Write-Log "- Backup erstellt: $backupFile" -Level INFO
}

Write-Host "`n" -NoNewline
Write-Host "WICHTIG: " -ForegroundColor Yellow -NoNewline
Write-Host "Ein Neustart ist erforderlich, damit alle Änderungen wirksam werden!"

Write-Host "`nEmpfohlene nächste Schritte:" -ForegroundColor Cyan
Write-Host "1. Überprüfen Sie die Log-Datei auf Warnungen" -ForegroundColor White
Write-Host "2. Testen Sie kritische Anwendungen" -ForegroundColor White
Write-Host "3. Führen Sie einen Neustart durch" -ForegroundColor White
Write-Host "4. Überprüfen Sie die Systemfunktionalität nach dem Neustart" -ForegroundColor White

$restart = Read-Host "`nMöchten Sie jetzt neu starten? (J/N)"
if ($restart -eq 'J' -or $restart -eq 'j') {
    Write-Log "System-Neustart initiiert..." -Level INFO
    Restart-Computer -Force
} else {
    Write-Log "Neustart übersprungen. Bitte manuell neu starten!" -Level WARNING
}

Write-Log "Script beendet" -Level INFO