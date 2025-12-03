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

# See full content in repository