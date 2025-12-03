<#
.SYNOPSIS
    Stellt Windows-Einstellungen aus einem Backup wieder her
    
.DESCRIPTION
    Dieses Script stellt Registry-Einstellungen aus einem zuvor erstellten Backup wieder her.
    Verwenden Sie es, wenn nach der Härtung Probleme auftreten.
    
.PARAMETER BackupFile
    Pfad zur Backup-JSON-Datei
    
.PARAMETER WhatIf
    Zeigt an, welche Änderungen vorgenommen würden, ohne sie auszuführen
    
.EXAMPLE
    .\Restore-FromBackup.ps1 -BackupFile "Backups\Backup_20251203_120000.json"
    
.EXAMPLE
    .\Restore-FromBackup.ps1 -BackupFile "Backups\Backup_20251203_120000.json" -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [string]$BackupFile,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

#Requires -RunAsAdministrator

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
}

Write-Host "`n=====================================================================" -ForegroundColor Cyan
Write-Host "  Windows Backup-Wiederherstellung" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

if ($WhatIf) {
    Write-Log "WhatIf-Modus aktiviert - keine Änderungen werden vorgenommen" -Level WARNING
}

# Backup-Datei laden
try {
    Write-Log "Lade Backup-Datei: $BackupFile" -Level INFO
    $backup = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
    
    Write-Log "Backup-Information:" -Level INFO
    Write-Log "  Erstellt am: $($backup.Timestamp)" -Level INFO
    Write-Log "  Computer: $($backup.ComputerName)" -Level INFO
    
    if ($backup.ComputerName -ne $env:COMPUTERNAME) {
        Write-Log "WARNUNG: Backup wurde auf einem anderen Computer erstellt!" -Level WARNING
        $continue = Read-Host "Trotzdem fortfahren? (J/N)"
        if ($continue -ne 'J') {
            Write-Log "Wiederherstellung abgebrochen" -Level WARNING
            exit
        }
    }
}
catch {
    Write-Log "Fehler beim Laden der Backup-Datei: $_" -Level ERROR
    exit 1
}

# Einstellungen wiederherstellen
$restoredCount = 0
$errorCount = 0

foreach ($registryPath in $backup.Settings.PSObject.Properties.Name) {
    Write-Log "`nWiederherstelle: $registryPath" -Level INFO
    
    $settings = $backup.Settings.$registryPath
    
    if (-not $settings) {
        Write-Log "Keine Einstellungen für diesen Pfad im Backup" -Level WARNING
        continue
    }
    
    # Registry-Pfad erstellen falls nicht vorhanden
    if (-not (Test-Path $registryPath)) {
        if ($WhatIf) {
            Write-Log "[WhatIf] Würde Registry-Pfad erstellen: $registryPath" -Level INFO
        }
        else {
            try {
                New-Item -Path $registryPath -Force | Out-Null
                Write-Log "Registry-Pfad erstellt: $registryPath" -Level SUCCESS
            }
            catch {
                Write-Log "Fehler beim Erstellen des Pfads: $_" -Level ERROR
                $errorCount++
                continue
            }
        }
    }
    
    # Alle Properties wiederherstellen
    foreach ($property in $settings.PSObject.Properties) {
        if ($property.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
            continue
        }
        
        $propertyName = $property.Name
        $propertyValue = $property.Value
        
        if ($null -eq $propertyValue) {
            continue
        }
        
        if ($WhatIf) {
            Write-Log "[WhatIf] Würde setzen: $propertyName = $propertyValue" -Level INFO
        }
        else {
            try {
                # Typ bestimmen
                $valueType = switch ($propertyValue.GetType().Name) {
                    'String'  { 'String' }
                    'Int32'   { 'DWord' }
                    'Int64'   { 'QWord' }
                    'Byte[]'  { 'Binary' }
                    default   { 'String' }
                }
                
                Set-ItemProperty -Path $registryPath -Name $propertyName -Value $propertyValue -Type $valueType -Force -ErrorAction Stop
                Write-Log "✓ Wiederhergestellt: $propertyName" -Level SUCCESS
                $restoredCount++
            }
            catch {
                Write-Log "✗ Fehler bei $propertyName : $_" -Level ERROR
                $errorCount++
            }
        }
    }
}

# Zusammenfassung
Write-Host "`n=====================================================================" -ForegroundColor Cyan
Write-Host "  Wiederherstellung abgeschlossen" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

if ($WhatIf) {
    Write-Log "WhatIf-Modus - keine tatsächlichen Änderungen vorgenommen" -Level INFO
}
else {
    Write-Log "Erfolgreich wiederhergestellt: $restoredCount Einstellungen" -Level SUCCESS
    if ($errorCount -gt 0) {
        Write-Log "Fehler bei: $errorCount Einstellungen" -Level ERROR
    }
    
    Write-Host "`nEin Neustart wird empfohlen, damit alle Änderungen wirksam werden." -ForegroundColor Yellow
    $restart = Read-Host "Möchten Sie jetzt neu starten? (J/N)"
    if ($restart -eq 'J' -or $restart -eq 'j') {
        Restart-Computer -Force
    }
}