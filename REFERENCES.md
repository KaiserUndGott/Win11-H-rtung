# Referenzen und Quellen

## Primäre Quelle

**iX-Artikel:** "IT-Sicherheit: Windows härten mit Microsoft-Tools"
- **Autor:** Christian Biehler
- **Datum:** 27.11.2025
- **Magazin:** iX - Magazin für professionelle Informationstechnik
- **URL:** https://www.heise.de/hintergrund/IT-Sicherheit-Windows-haerten-mit-Microsoft-Tools-11080657.html

## Microsoft Security Compliance Toolkit (SCT)

### Download und Dokumentation
- **SCT Download:** https://www.microsoft.com/en-us/download/details.aspx?id=55319
- **Komponenten:**
  - LGPO (Local Group Policy Object Utility) - Version 3.0
  - Policy Analyzer - Version 4.0
  - Security Baselines für Windows 11, Server 2025, Microsoft 365, Edge

### Microsoft Dokumentation
- **Windows Security Baselines:**
  https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines

- **Device Guard Deployment:**
  https://learn.microsoft.com/en-us/windows/security/threat-protection/device-guard/introduction-to-device-guard-virtualization-based-security-and-windows-defender-application-control

- **Credential Guard:**
  https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard

- **Windows Defender Application Control (WDAC):**
  https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control

## DISA STIG (Security Technical Implementation Guide)

### Downloads
- **STIG Viewer & GPOs:** https://public.cyber.mil/stigs/downloads/
- **Windows 11 STIG:** https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=windows
- **STIG Bundle (GPOs):** Aktuellste Version - Juli 2025

### Dokumentation
- **STIG Overview:** https://public.cyber.mil/stigs/
- **Implementation Guide:** Enthalten in den STIG-Downloads

## CIS Benchmarks

### Center for Internet Security
- **CIS Homepage:** https://www.cisecurity.org/
- **Windows 11 Benchmark:** https://www.cisecurity.org/benchmark/microsoft_windows_desktop
- **CIS Controls:** https://www.cisecurity.org/controls

**Hinweis:** CIS Benchmarks erfordern meist eine Registrierung für den Download.

## Weitere Microsoft-Ressourcen

### Security Development
- **Security Development Lifecycle (SDL):**
  https://www.microsoft.com/en-us/securityengineering/sdl/

- **Microsoft Security Blog:**
  https://www.microsoft.com/en-us/security/blog/

- **Windows Security Updates:**
  https://msrc.microsoft.com/update-guide

### PowerShell Security
- **PowerShell Logging:**
  https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf/whats-new/script-logging

- **PowerShell Execution Policies:**
  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies

### Windows Defender
- **Windows Defender Antivirus:**
  https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows

- **Attack Surface Reduction (ASR):**
  https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction

## NSA Cybersecurity Guidance

### National Security Agency
- **NSA Cybersecurity Advisories:**
  https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/

- **Windows 10/11 Hardening Guidance:**
  https://media.defense.gov/2023/Apr/12/2003198742/-1/-1/0/CSI_KEEPING_UP_WITH_THE_PATCHING_JONESES.PDF

## BSI Empfehlungen (Bundesamt für Sicherheit in der Informationstechnik)

### Deutsche Sicherheitsleitlinien
- **BSI IT-Grundschutz:**
  https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/it-grundschutz_node.html

- **SiSyPHuS Win10 (Windows Sicherheit):**
  https://www.bsi.bund.de/DE/Themen/Oeffentliche-Verwaltung/Moderner-Arbeitsplatz/SiSyPHuS_Win10/SiSyPHuS_node.html

## Zusätzliche Tools und Ressourcen

### Hardening-Tools
- **HardenTools (Security Without Borders):**
  https://github.com/securitywithoutborders/hardentools

- **Windows 10 Hardening GitHub Collection:**
  https://github.com/0x6d69636b/windows_hardening

### Benchmarking & Testing
- **Security Configuration Wizard:**
  Integriert in Windows Server

- **Microsoft Baseline Security Analyzer (MBSA):**
  Deprecated, ersetzt durch Update Management

- **Windows Security Compliance Toolkit (PolicyAnalyzer):**
  Teil des SCT

## Wichtige GPO-Pfade und Registry-Keys

### Dokumentation der im Script verwendeten Registry-Pfade

#### Device Guard / Credential Guard
```
HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard
```

#### Windows Defender
```
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet
```

#### PowerShell Logging
```
HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
```

#### User Account Control
```
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
```

#### Netzwerk
```
HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters
HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
```

## Weitere Artikel der iX-Reihe

Wie im Artikel erwähnt, weitere relevante iX-Artikel:

1. **"Mit freien Werkzeugen auf Malwarepirsch"**
   
2. **"Das Post-Exploitation-Framework Empire"**
   
3. **"Wazuh: IT-Schutz mit Open Source"**
   
4. **"Einfaches Logmanagement mit Logging Made Easy"**
   
5. **"Open-Source-Tool Nuclei für Schwachstellenscans"**
   
6. **"IT-Sicherheit: Mit KI Schwachstellen finden und ausnutzen"**
   https://www.heise.de/ratgeber/IT-Sicherheit-Mit-KI-Schwachstellen-finden-und-ausnutzen-10517021.html

7. **"BBOT: Angriffsflächen automatisch erkennen und Risiken reduzieren"**
   https://www.heise.de/tests/BBOT-Angriffsflaechen-automatisch-erkennen-und-Risiken-reduzieren-11079481.html

## Community-Ressourcen

### Reddit
- **r/sysadmin:** https://www.reddit.com/r/sysadmin/
- **r/PowerShell:** https://www.reddit.com/r/PowerShell/
- **r/cybersecurity:** https://www.reddit.com/r/cybersecurity/

### GitHub
- Suche nach: "windows hardening", "windows security baseline", "gpo hardening"

## Schulungen und Zertifizierungen

### Microsoft
- **Microsoft Certified: Security, Compliance, and Identity Fundamentals**
- **Microsoft Certified: Security Operations Analyst Associate**

### Andere
- **CompTIA Security+**
- **GIAC Security Essentials (GSEC)**
- **Certified Information Systems Security Professional (CISSP)**

## Bücher

### Empfohlene Fachliteratur
1. **"Windows Security Internals"** - James Forshaw
2. **"Windows Internals"** - Mark Russinovich et al.
3. **"Cybersecurity Blue Team Strategies"** - Kunal Sehgal

## Hinweise zur Nutzung dieser Referenzen

### Aktualität
- Prüfen Sie immer die neuesten Versionen der Security Baselines
- STIG und CIS Benchmarks werden regelmäßig aktualisiert
- Microsoft ändert Empfehlungen mit neuen Windows-Versionen

### Kontext
- Nicht alle Empfehlungen sind für jede Umgebung geeignet
- Testen Sie Änderungen immer in einer Testumgebung
- Dokumentieren Sie Abweichungen von Standards

### Kombinationen
- SCT, STIG und CIS ergänzen sich, widersprechen sich teilweise aber auch
- Verwenden Sie den Policy Analyzer für Vergleiche
- Erstellen Sie Ihre eigene Baseline basierend auf Ihren Anforderungen

## Updates und Änderungen

Diese Referenzliste wird basierend auf dem Stand **Dezember 2025** gepflegt.

**Letzte Überprüfung der Links:** Dezember 2025

---

## Disclaimer

Die in diesem Dokument aufgeführten Links und Ressourcen dienen ausschließlich Informationszwecken. Die Nutzung erfolgt auf eigene Verantwortung. Prüfen Sie immer die Aktualität und Anwendbarkeit für Ihre spezifische Umgebung.

---

**Zusammengestellt für:** Windows-Hardening Script Collection
**Version:** 1.0
**Datum:** Dezember 2025