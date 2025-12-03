# Windows 11 Professional Härtungs-Script

![Windows 11](https://img.shields.io/badge/Windows%2011-0078D4?style=for-the-badge&logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Security](https://img.shields.io/badge/Security-Critical-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 🔒 Übersicht

Umfassendes PowerShell-Script zur **Härtung von Windows 11 Professional** Stand-alone Installationen basierend auf:
- **Microsoft Security Compliance Toolkit (SCT)**
- **DISA STIG** (Security Technical Implementation Guide)
- **CIS Benchmarks**
- **iX-Artikel** "Windows härten mit Microsoft-Tools" (Nov. 2025)

## ✨ Features

### 🛡️ 10 Härtungskategorien

1. **Device Guard & Credential Guard** - LSA Protection, HVCI, VBS
2. **Windows Defender** - Echtzeit-Schutz, Cloud-Schutz, Exploit Guard
3. **PowerShell Security** - Script Block Logging, Transcription
4. **User Account Control** - Erhöhtes UAC-Level
5. **Netzwerk-Härtung** - SMBv1 aus, SMB Signing, LLMNR deaktiviert
6. **Remote Desktop** - NLA, SSL/TLS-Verschlüsselung
7. **Audit-Richtlinien** - Erweiterte Ereignisprotokollierung
8. **Windows Update** - Automatische Updates
9. **Anmelde-Richtlinien** - Passwortlänge, Account Lockout
10. **Zusätzliche Maßnahmen** - AutoRun aus, NTLMv2, Event Logs

### 🎯 Highlights

- ✅ **Automatisches Backup** vor jeder Änderung
- ✅ **Detailliertes Logging** aller Änderungen
- ✅ **Rollback-Funktion** bei Problemen
- ✅ **Status-Checks** mit HTML-Reports
- ✅ **Umfassende Dokumentation** (Deutsch)

## 🚀 Quick Start

```powershell
# 1. Repository klonen
git clone https://github.com/KaiserUndGott/Win11-Härtung.git
cd Win11-Härtung

# 2. PowerShell als Administrator öffnen

# 3. Execution Policy anpassen
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# 4. Script ausführen
.\Harden-Windows11.ps1
```

**Detaillierte Anleitung:** Siehe [QUICK-START.md](QUICK-START.md)

## 📋 Voraussetzungen

- Windows 11 Professional oder höher
- Administratorrechte
- PowerShell 5.1+
- TPM 2.0 (für Device Guard)

## 📂 Dateien

| Datei | Beschreibung |
|-------|--------------|
| `Harden-Windows11.ps1` | Hauptscript zur Härtung |
| `Check-Hardening.ps1` | Status-Überprüfung |
| `Restore-FromBackup.ps1` | Backup-Wiederherstellung |
| `README.md` | Vollständige Dokumentation |
| `QUICK-START.md` | 5-Minuten Schnelleinstieg |
| `CHECKLIST.md` | Post-Hardening Checkliste |
| `REFERENCES.md` | Quellen und Links |

## ⚠️ Wichtige Hinweise

- ⚠️ **Backup erstellen** vor Ausführung!
- ⚠️ In **Testumgebung** testen
- ⚠️ **Dokumentation lesen**
- ⚠️ Neustart nach Härtung erforderlich

## 📖 Dokumentation

- [📘 Vollständige Dokumentation](README.md)
- [🚀 Quick-Start Guide](QUICK-START.md)
- [✅ Post-Hardening Checkliste](CHECKLIST.md)
- [📚 Referenzen & Quellen](REFERENCES.md)
- [📝 Changelog](CHANGELOG.md)
- [⚖️ Lizenz & Haftungsausschluss](LICENSE.md)

## 🤝 Mitwirken

Verbesserungsvorschläge und Fehlermeldungen sind willkommen!

1. Fork erstellen
2. Feature-Branch erstellen
3. Änderungen committen
4. Pull Request erstellen

## 📜 Lizenz

MIT License - Siehe [LICENSE.md](LICENSE.md)

**Haftungsausschluss:** Verwendung auf eigene Gefahr. Siehe [LICENSE.md](LICENSE.md)

## 🙏 Danksagung

Basiert auf dem iX-Artikel "Windows härten mit Microsoft-Tools" von **Christian Biehler** (27.11.2025)

## 📊 Version

**Version:** 1.0  
**Datum:** Dezember 2025  
**Status:** Stable

---

**⭐ Gefällt dir das Projekt? Gib einen Stern!**
