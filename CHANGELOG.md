# Changelog

Alle wichtigen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/).

## [1.0.0] - 2025-12-03

### Hinzugefügt
- Initiales Release des Windows 11 Härtungs-Scripts
- Hauptscript `Harden-Windows11.ps1` mit 10 Härtungskategorien
- Überprüfungs-Script `Check-Hardening.ps1` mit HTML-Export
- Wiederherstellungs-Script `Restore-FromBackup.ps1`
- Umfassende Dokumentation (README.md, QUICK-START.md, CHECKLIST.md)
- Referenzliste mit allen Quellen (REFERENCES.md)

### Härtungs-Features
- Device Guard und Credential Guard Konfiguration
- Windows Defender Optimierung
- PowerShell Security (Logging, Transcription)
- User Account Control (UAC) Härtung
- Netzwerk-Sicherheit (SMB, LLMNR, NetBIOS)
- Remote Desktop Protokoll (RDP) Absicherung
- Erweiterte Audit-Richtlinien
- Windows Update Konfiguration
- Anmelde- und Lockout-Richtlinien
- Zusätzliche Registry-Härtungen

### Basis
- Basiert auf iX-Artikel "Windows härten mit Microsoft-Tools" (27.11.2025)
- Implementiert Best Practices aus Microsoft SCT, STIG, und CIS
- Getestet auf Windows 11 Professional 24H2

---

## [Geplant] - Zukünftige Versionen

### Version 1.1.0 - Geplant
- [ ] Integration mit Microsoft Intune
- [ ] AppLocker / WDAC Policies
- [ ] BitLocker Management
- [ ] Windows Firewall Härteprofile

### Version 1.2.0 - Geplant
- [ ] GUI für einfachere Bedienung
- [ ] Profil-System (Basic, Standard, High Security)
- [ ] Automatische Updates des Scripts

---

## Support-Hinweise

- ✅ Windows 11 Professional: Vollständig unterstützt
- ✅ Windows 11 Enterprise: Vollständig unterstützt
- ⚠️ Windows 11 Home: Teilweise unterstützt
- ❌ Windows 10: Nicht getestet

---

**Letzte Aktualisierung:** 2025-12-03
