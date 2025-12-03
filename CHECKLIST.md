# Post-Hardening Checkliste

Diese Checkliste hilft Ihnen, nach der Härtung systematisch zu überprüfen, ob alles korrekt funktioniert.

## ✅ Unmittelbar nach der Härtung

### 1. Log-Dateien prüfen
- [ ] Log-Datei im `Logs`-Ordner öffnen
- [ ] Auf ERROR-Meldungen prüfen
- [ ] Auf WARNING-Meldungen prüfen
- [ ] Anzahl der Änderungen notieren: _________

### 2. Backup sichern
- [ ] Backup-Datei im `Backups`-Ordner gefunden
- [ ] Backup-Datei an sicheren Ort kopieren (z.B. externes Laufwerk)
- [ ] Backup-Pfad notieren: _________________________________

### 3. Neustart durchführen
- [ ] Alle offenen Programme schließen
- [ ] Arbeiten speichern
- [ ] System neu starten

---

## ✅ Nach dem Neustart

### 4. Grundlegende Systemfunktionen

- [ ] System startet normal
- [ ] Anmeldung funktioniert
- [ ] Desktop wird korrekt angezeigt
- [ ] Netzwerkverbindung funktioniert
- [ ] Internetzugriff vorhanden

### 5. Check-Script ausführen

```powershell
cd "C:\Pfad\zu\Windows-Hardening"
.\Check-Hardening.ps1 -ExportPath "C:\Reports\Hardening-Check.html"
```

- [ ] Check-Script ausgeführt
- [ ] Anzahl OK-Werte: _________ / _________
- [ ] Abweichungen prüfen und dokumentieren
- [ ] HTML-Report gespeichert

### 6. Windows Defender testen

- [ ] Windows Security öffnen (Windows + I → Datenschutz & Sicherheit → Windows-Sicherheit)
- [ ] Viren- & Bedrohungsschutz: ✅ Grün
- [ ] Echtzeitschutz: **EIN**
- [ ] Cloudbasierter Schutz: **EIN**
- [ ] Manipulationsschutz: **EIN**

**Test:**
```powershell
# EICAR Test-String (harmlos, wird von Defender erkannt)
# NUR ZUM TESTEN - wird sofort gelöscht!
```
- [ ] Defender erkennt Testdatei und blockiert sie

### 7. Event Viewer prüfen

1. Event Viewer öffnen: `eventvwr.msc`
2. Windows-Protokolle überprüfen:

**System:**
- [ ] Keine kritischen Fehler (rot) seit Neustart
- [ ] Warnungen (gelb) prüfen und notieren

**Sicherheit:**
- [ ] Audit-Ereignisse werden protokolliert
- [ ] Keine ungewöhnlichen Anmeldefehler

**Anwendung:**
- [ ] Keine kritischen Anwendungsfehler

### 8. Device Guard / Credential Guard

Nur wenn Device Guard aktiviert wurde:

```powershell
# Credential Guard Status prüfen
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

- [ ] `VirtualizationBasedSecurityStatus` = 2 (Running)
- [ ] `SecurityServicesRunning` enthält 1 (Credential Guard)

**Alternative Prüfung:**
```powershell
msinfo32.exe
```
- [ ] Bei "Systemübersicht" → "Virtualisierungsbasierte Sicherheit" = "Wird ausgeführt"

---

## ✅ Anwendungstests (in den nächsten 24-48 Stunden)

### 9. Kritische Geschäftsanwendungen

Liste Ihrer wichtigen Programme:

1. [ ] _________________________ funktioniert
2. [ ] _________________________ funktioniert
3. [ ] _________________________ funktioniert
4. [ ] _________________________ funktioniert
5. [ ] _________________________ funktioniert

### 10. Netzwerk-Funktionen

**Dateifreigaben:**
- [ ] Zugriff auf Netzlaufwerke funktioniert
- [ ] Zugriff auf freigegebene Ordner funktioniert
- [ ] Dateien können kopiert werden

**Drucker:**
- [ ] Netzwerkdrucker erreichbar
- [ ] Testdruck erfolgreich

**VPN (falls verwendet):**
- [ ] VPN-Verbindung kann aufgebaut werden
- [ ] Zugriff auf Ressourcen über VPN funktioniert

### 11. Remote-Zugriff (falls aktiviert)

**Remote Desktop:**
```powershell
# RDP-Status prüfen
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
# Wert 0 = RDP aktiviert
```

- [ ] Remote Desktop Verbindung von anderem PC testen
- [ ] NLA (Network Level Authentication) funktioniert
- [ ] Anmeldung erfolgreich

### 12. PowerShell-Scripts

Falls Sie PowerShell-Scripts verwenden:

- [ ] Signierte Scripts laufen weiterhin
- [ ] Execution Policy prüfen: `Get-ExecutionPolicy`
- [ ] Script-Logging wird erstellt (C:\PSTranscripts)

**Wichtig:** Script Block Logging kann viel Speicherplatz belegen!

---

## ✅ Sicherheitsprüfungen

### 13. Benutzerkonten

- [ ] Standard-Benutzerkonto funktioniert normal
- [ ] UAC-Abfragen erscheinen bei Admin-Aktionen
- [ ] Administrator-Konto nur wenn nötig verwendbar

### 14. Passwort-Richtlinien

```powershell
net accounts
```

- [ ] Minimale Passwortlänge: 12 oder mehr
- [ ] Konto-Sperrungsschwelle: 5 oder weniger
- [ ] Konto-Sperrdauer: 30 Minuten oder mehr

### 15. Windows Update

- [ ] Windows Update öffnen
- [ ] Nach Updates suchen
- [ ] Ausstehende Updates installieren
- [ ] Neustart falls erforderlich

### 16. Firewall

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled
```

- [ ] Alle Profile aktiviert (Domain, Private, Public)
- [ ] Notwendige Programme haben Firewall-Regeln

---

## ✅ Performance-Überwachung

### 17. Ressourcen-Verbrauch

Task-Manager öffnen (Strg+Shift+Esc):

**Leerlauf:**
- [ ] CPU-Auslastung: < 10%
- [ ] RAM-Nutzung: Normal für Ihr System
- [ ] Festplatte: Keine Dauerlast

**Unter Last:**
- [ ] Keine ungewöhnlichen Prozesse mit hoher CPU-Last
- [ ] System reagiert flüssig

### 18. Boot-Zeit

- [ ] Boot-Zeit dokumentieren (vor Härtung): _______ Sekunden
- [ ] Boot-Zeit dokumentieren (nach Härtung): _______ Sekunden
- [ ] Unterschied akzeptabel (< 10 Sekunden länger)

---

## ✅ Langzeitbeobachtung (1 Woche)

### 19. Tägliche Checks

Tag 1: [ ] Keine Probleme
Tag 2: [ ] Keine Probleme
Tag 3: [ ] Keine Probleme
Tag 4: [ ] Keine Probleme
Tag 5: [ ] Keine Probleme
Tag 6: [ ] Keine Probleme
Tag 7: [ ] Keine Probleme

### 20. Probleme dokumentieren

Falls Probleme auftreten:

| Datum | Problem | Anwendung | Lösung | Erledigt |
|-------|---------|-----------|--------|----------|
|       |         |           |        | [ ]      |
|       |         |           |        | [ ]      |
|       |         |           |        | [ ]      |

---

## ❌ Rollback bei Problemen

Falls schwerwiegende Probleme auftreten:

### Option 1: Einzelne Einstellungen zurücksetzen
```powershell
# Beispiel: Device Guard deaktivieren
.\Harden-Windows11.ps1 -SkipDeviceGuard
```

### Option 2: Komplettes Backup wiederherstellen
```powershell
.\Restore-FromBackup.ps1 -BackupFile "Backups\Backup_YYYYMMDD_HHMMSS.json"
```

### Option 3: Systemwiederherstellungspunkt
1. Windows + R → `rstrui.exe`
2. Wiederherstellungspunkt vor Härtung wählen
3. Wiederherstellen

---

## 📋 Zusätzliche Empfehlungen

Nach erfolgreicher Härtung sollten Sie auch:

### BitLocker aktivieren (falls nicht vorhanden)
```powershell
# Prüfen ob TPM vorhanden
Get-Tpm

# BitLocker aktivieren (GUI)
# Start → Einstellungen → Datenschutz und Sicherheit → Geräteverschlüsselung
```
- [ ] BitLocker auf Systemlaufwerk aktiviert
- [ ] Wiederherstellungsschlüssel gesichert

### Windows Firewall konfigurieren
- [ ] Firewall-Regeln für benötigte Programme erstellt
- [ ] Ungenutzte Dienste blockiert
- [ ] Logging aktiviert (optional)

### Regelmäßige Wartung planen
- [ ] Wöchentliche Windows Updates
- [ ] Monatliche Sicherheitsüberprüfung mit Check-Script
- [ ] Vierteljährliche Review der Härtungseinstellungen
- [ ] Jährliche Komplettprüfung gegen STIG/CIS Benchmarks

### Dokumentation
- [ ] Diese Checkliste ausgefüllt und archiviert
- [ ] System-Konfiguration dokumentiert
- [ ] Backup-Standorte notiert
- [ ] Ansprechpartner für Probleme definiert

---

## 📊 Härtungs-Score

Zählen Sie Ihre ✅:

- **0-30 Punkte:** Grundlegende Prüfung abgeschlossen
- **31-60 Punkte:** Gründliche Überprüfung durchgeführt
- **61-90 Punkte:** Exzellente, umfassende Validierung
- **Alle Punkte:** Professionelle IT-Security-Prüfung! 🏆

---

**Datum der Prüfung:** ____________________

**Durchgeführt von:** ____________________

**Unterschrift:** ____________________

---

## Notizen

Platz für zusätzliche Beobachtungen, Probleme oder Anpassungen:

_______________________________________________________________________________

_______________________________________________________________________________

_______________________________________________________________________________

_______________________________________________________________________________

_______________________________________________________________________________