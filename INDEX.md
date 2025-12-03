# Windows Hardening - Verzeichnisstruktur

```
Windows-Hardening/
│
├── Harden-Windows11.ps1          # Hauptscript zur Härtung
├── Check-Hardening.ps1            # Überprüfungs-Script
├── Restore-FromBackup.ps1         # Backup-Wiederherstellung
│
├── README.md                      # Vollständige Dokumentation
├── QUICK-START.md                 # Schnelleinstieg (5 Minuten)
├── CHECKLIST.md                   # Post-Hardening Checkliste
├── REFERENCES.md                  # Quellen und Referenzen
│
├── Logs/                          # Wird automatisch erstellt
│   └── Hardening_YYYYMMDD.log    # Änderungsprotokolle
│
└── Backups/                       # Wird automatisch erstellt
    └── Backup_YYYYMMDD_HHMMSS.json # Registry-Backups
```

## Verwendung

### Erste Schritte
1. Lesen: `QUICK-START.md` (5 Minuten)
2. Ausführen: `Harden-Windows11.ps1`
3. Prüfen: `Check-Hardening.ps1`
4. Checkliste: `CHECKLIST.md`

### Erweiterte Nutzung
- Vollständige Infos: `README.md`
- Quellen & Benchmarks: `REFERENCES.md`
- Bei Problemen: `Restore-FromBackup.ps1`

---

Erstellt: Dezember 2025
Basierend auf: iX-Artikel "Windows härten mit Microsoft-Tools"