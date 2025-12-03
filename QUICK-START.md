# Quick-Start Guide - Windows 11 Härtung

## 🚀 In 5 Minuten zur gehärteten Windows-Installation

### Schritt 1: Vorbereitung (2 Minuten)

1. **Vollständiges System-Backup erstellen**
   - Windows Backup oder
   - Disk-Image mit Acronis/Macrium Reflect/o.ä.

2. **Wiederherstellungspunkt erstellen**
   ```
   Windows + R → sysdm.cpl → Tab "Computerschutz" 
   → "Erstellen..." → Namen vergeben → OK
   ```

3. **PowerShell als Administrator öffnen**
   - Windows + X
   - "Terminal (Administrator)" auswählen

### Schritt 2: Script ausführen (1 Minute)

```powershell
# Zum Ordner navigieren
cd "C:\Win11-Härtung"

# Execution Policy temporär anpassen
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Script ausführen
.\Harden-Windows11.ps1
```

**Das Script wird:**
- ✅ Automatisch ein Backup erstellen
- ✅ Alle Änderungen loggen
- ✅ Am Ende zum Neustart auffordern

### Schritt 3: Neustart (1 Minute)

- Bestätigen Sie den Neustart mit **J**
- System wird neu gestartet

### Schritt 4: Überprüfung (1 Minute)

Nach dem Neustart:

```powershell
cd "C:\Win11-Härtung"
.\Check-Hardening.ps1
```

**Fertig! 🎉**

---

## 🎯 Was wird gehärtet?

| Bereich | Maßnahmen |
|---------|-----------|
| **Device Guard** | Credential Guard, HVCI, VBS |
| **Windows Defender** | Echtzeit-Schutz, Cloud-Schutz, Exploit Guard |
| **PowerShell** | Script Block Logging, Transcription |
| **UAC** | Erhöhtes Sicherheitslevel |
| **Netzwerk** | SMBv1 aus, LLMNR aus, SMB Signing |
| **RDP** | NLA, hohe Verschlüsselung |
| **Audit** | Erweiterte Ereignisprotokollierung |
| **Passwörter** | Min. 12 Zeichen, Account Lockout |
| **Sonstiges** | AutoRun aus, NTLMv2, Event Log-Größen |

---

## ⚠️ Wichtige Hinweise

### Kompatibilität
- ✅ Windows 11 Professional oder höher
- ✅ TPM 2.0 für Device Guard empfohlen
- ✅ UEFI + Secure Boot für beste Sicherheit

### Bei Problemen
```powershell
# Device Guard überspringen
.\Harden-Windows11.ps1 -SkipDeviceGuard

# Backup wiederherstellen
.\Restore-FromBackup.ps1 -BackupFile "Backups\Backup_*.json"
```

---

**Los geht's! 🚀**
