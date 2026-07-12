<div align="center">

# 🛡️ Wazuh Alert Trigger - All Levels

**Déclencheur complet des niveaux d'alerte Wazuh (1-15) pour environnements de test Windows**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=for-the-badge&logo=PowerShell&logoColor=white)](https://learn.microsoft.com/fr-fr/powershell/)
[![Windows](https://img.shields.io/badge/Windows-10%2F11%2FServer_2016%2B-0078D6?style=for-the-badge&logo=Windows&logoColor=white)](https://www.microsoft.com/windows)
[![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-4CB848?style=for-the-badge&logo=Wazuh&logoColor=white)](https://wazuh.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0-blue?style=for-the-badge)]()
[![Admin Required](https://img.shields.io/badge/Privil%C3%A8ges-Administrateur-red?style=for-the-badge)]()
[![Test Only](https://img.shields.io/badge/Environnement-TEST__ONLY-orange?style=for-the-badge)]()
[![Platform](https://img.shields.io/badge/Platform-x64__x86-lightgrey?style=for-the-badge)]()

<br />

**Auteur : [DilaneNg](https://github.com/DilaneNg)**

[![GitHub](https://img.shields.io/badge/GitHub-DilaneNg-181717?style=flat-square&logo=GitHub)](https://github.com/DilaneNg)
[![Project](https://img.shields.io/badge/Repo-Wazuh__Alert__Trigger__All__Levels-181717?style=flat-square&logo=GitHub)](https://github.com/DilaneNg/Wazuh-Alert-Trigger-All-Levels)
[![Date](https://img.shields.io/badge/Date-2026--07--12-blue?style=flat-square)]()

<br />

[![Alert Levels](https://img.shields.io/badge/Niveaux_1%2D2-Informational-30A9DE?style=flat-square)](#)
[![Alert Levels](https://img.shields.io/badge/Niveau_3-Low-yellow?style=flat-square)](#)
[![Alert Levels](https://img.shields.io/badge/Niveau_4-System-yellow?style=flat-square)](#)
[![Alert Levels](https://img.shields.io/badge/Niveau_5-User%2FSystem-yellow?style=flat-square)](#)
[![Alert Levels](https://img.shields.io/badge/Niveaux_6%2D7-Reconnaissance%2FAttack-orange?style=flat-square)](#)
[![Alert Levels](https://img.shields.io/badge/Niveau_8-Recognized_Attack-orange?style=flat-square)](#)
[![Alert Levels](https://img.shields.io/badge/Niveau_9-Policy_Violation-red?style=flat-square)](#)
[![Alert Levels](https://img.shields.io/badge/Niveaux_10%2D11-Malware%2FCritical-red?style=flat-square)](#)
[![Alert Levels](https://img.shields.io/badge/Niveaux_12%2D13-Rootkit%2FCritical_System-darkred?style=flat-square)](#)
[![Alert Levels](https://img.shields.io/badge/Niveaux_14%2D15-Emergency%2FIntrusion-9B111E?style=flat-square)](#)

</div>

---

> ⚠️ **AVERTISSEMENT IMPORTANT**
>
> Ce script est conçu **EXCLUSIVEMENT pour les environnements de test et de laboratoire**.
> Il génère volontairement des événements malveillants simulés (injections, mimikatz, ransomware, rootkits, etc.).
> **Ne l'exécutez JAMAIS sur un système de production.**

---

## 📋 Table des matières

- [À propos](#-à-propos)
- [Fonctionnalités](#-fonctionnalités)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
  - [Exécution complète](#exécution-complète-niveaux-1-15)
  - [Niveau spécifique](#niveau-spécifique)
  - [Mode sans danger](#mode-sans-danger-skipdangerous)
  - [Mode simulation](#mode-simulation-whatif)
  - [Mode aléatoire](#mode-aléatoire-random)
  - [Mode continu](#mode-continu-loop)
  - [Rapports de sortie](#rapports-de-sortie)
- [Niveaux d'alerte détaillés](#-niveaux-dalerte-détaillés)
- [Paramètres](#-paramètres)
- [Rapports générés](#-rapports-générés)
- [Architecture du script](#-architecture-du-script)
- [Sécurité et nettoyage](#-sécurité-et-nettoyage)
- [Contribuer](#-contribuer)
- [Licence](#-licence)
- [Auteur](#-auteur)

---

## 🎯 À propos

**Wazuh Alert Trigger - All Levels** est un script PowerShell professionnel conçu pour tester et valider le fonctionnement d'un déploiement Wazuh SIEM. Il génère volontairement des événements Windows qui déclenchent les **15 niveaux d'alerte Wazuh**, couvrant l'intégralité de la gamme de sévérité : des simples événements informatifs jusqu'aux intrusions confirmées.

### Pourquoi ce script ?

Lors du déploiement ou de la configuration d'un SIEM Wazuh, il est essentiel de vérifier que :
- Les règles de détection sont correctement configurées pour chaque niveau de sévérité
- Les alertes remontent correctement dans le dashboard Wazuh
- Les notifications (email, Slack, etc.) fonctionnent pour les niveaux critiques
- Les intégrations et les réponses automatiques sont opérationnelles

Ce script automatise entièrement ce processus de validation en simulant plus de **100 actions réparties sur 15 niveaux** en une seule exécution.

---

## ✨ Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| 🎯 **15 niveaux d'alerte** | Couverture complète des niveaux Wazuh 1 à 15 |
| 🔄 **Mode continu (Loop)** | Génération périodique d'événements (intervalle configurable de 5s à 3600s) |
| 🎲 **Mode aléatoire** | Exécution de 3 à 5 niveaux sélectionnés aléatoirement |
| 🛡️ **Mode sans danger** | `-SkipDangerous` exclut les niveaux 12-15 (actions destructrices simulées) |
| 🔍 **Mode simulation** | Support natif de `-WhatIf` pour visualiser les actions sans les exécuter |
| 📊 **Rapports multi-format** | Sortie Console, JSON et HTML avec dashboard visuel stylisé |
| 📝 **Logging complet** | Fichiers de logs horodatés avec niveaux de sévérité (INFO, OK, WARN, FAIL, DEBUG) |
| 🧹 **Nettoyage automatique** | Suppression de tous les artefacts de test en fin d'exécution |
| 📈 **Barre de progression** | Suivi visuel de l'avancement en temps réel |
| 🔐 **Vérification admin** | Contrôle obligatoire des privilèges administrateur avant exécution |
| 📁 **Niveau spécifique** | Exécution d'un niveau précis avec `-Level N` |
| 🗂️ **Suivi par niveau** | Enregistrement détaillé des résultats (succès/échec) pour chaque niveau |

---

## 📦 Prérequis

| Composant | Version minimale | Obligatoire |
|---|---|---|
| ![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=flat-square&logo=PowerShell&logoColor=white) | 5.1 | ✅ |
| ![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D6?style=flat-square&logo=Windows&logoColor=white) | Windows 10 / Server 2016+ | ✅ |
| ![Admin](https://img.shields.io/badge/Admin-Required-red?style=flat-square) | Privilèges Administrateur | ✅ |
| ![Wazuh Agent](https://img.shields.io/badge/Wazuh_Agent-Installé-4CB848?style=flat-square&logo=Wazuh&logoColor=white) | 4.x+ | ⚠️ Recommandé |

> Le script nécessite des **privilèges administrateur** pour écrire dans les journaux d'événements, modifier le registre, créer des tâches planifiées et accéder aux ressources système protégées.

---

## 🚀 Installation

```powershell
# 1. Cloner le dépôt
git clone https://github.com/DilaneNg/Wazuh-Alert-Trigger-All-Levels.git
cd Wazuh-Alert-Trigger-All-Levels

# 2. (Recommandé) Vérifier la politique d'exécution
Get-ExecutionPolicy

# 3. Exécuter le script en tant qu'administrateur
.\Wazuh_Alert_Trigger_All_Levels.ps1
```

> 💡 **Conseil** : Si vous rencontrez des erreurs liées à la politique d'exécution, exécutez dans une console PowerShell administrateur :
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> ```

---

## 📖 Utilisation

### Exécution complète (Niveaux 1-15)

Déclenche l'intégralité des 15 niveaux d'alerte :

```powershell
.\Wazuh_Alert_Trigger_All_Levels.ps1
```

### Niveau spécifique

Exécute uniquement un niveau d'alerte précis (1 à 15) :

```powershell
.\Wazuh_Alert_Trigger_All_Levels.ps1 -Level 7
```

### Mode sans danger (`-SkipDangerous`)

Exécute les niveaux 1 à 11 uniquement, en ignorant les actions potentiellement destructrices des niveaux 12 à 15 (rootkits, ransomware simulé, intrusions) :

```powershell
.\Wazuh_Alert_Trigger_All_Levels.ps1 -SkipDangerous
```

### Mode simulation (`-WhatIf`)

Affiche toutes les actions prévues sans les exécuter réellement. Idéal pour vérifier ce que le script ferait avant de l'exécuter :

```powershell
.\Wazuh_Alert_Trigger_All_Levels.ps1 -WhatIf
```

### Mode aléatoire (`-Random`)

Exécute un sous-ensemble aléatoire de 3 à 5 groupes de niveaux :

```powershell
.\Wazuh_Alert_Trigger_All_Levels.ps1 -Random
```

### Mode continu (`-Loop`)

Génère des événements en boucle avec un intervalle configurable. Chaque itération sélectionne 1 à 2 niveaux aléatoires. Appuyez sur `Ctrl+C` pour arrêter :

```powershell
# Boucle avec intervalle par défaut (30 secondes)
.\Wazuh_Alert_Trigger_All_Levels.ps1 -Loop

# Boucle avec intervalle personnalisé (60 secondes)
.\Wazuh_Alert_Trigger_All_Levels.ps1 -Loop -LoopInterval 60
```

### Rapports de sortie

Générez des rapports dans différents formats pour documenter vos tests :

```powershell
# Rapport console (par défaut)
.\Wazuh_Alert_Trigger_All_Levels.ps1 -ReportFormat Console

# Rapport JSON (machine-readable)
.\Wazuh_Alert_Trigger_All_Levels.ps1 -ReportFormat JSON

# Rapport HTML (dashboard visuel stylisé)
.\Wazuh_Alert_Trigger_All_Levels.ps1 -ReportFormat HTML
```

### Combinaison de paramètres

Les paramètres peuvent être combinés librement :

```powershell
# Simulation d'un niveau spécifique avec rapport JSON
.\Wazuh_Alert_Trigger_All_Levels.ps1 -Level 10 -WhatIf -ReportFormat JSON

# Mode sans danger en boucle toutes les 45 secondes
.\Wazuh_Alert_Trigger_All_Levels.ps1 -SkipDangerous -Loop -LoopInterval 45 -ReportFormat HTML

# Niveaux aléatoires avec rapport HTML
.\Wazuh_Alert_Trigger_All_Levels.ps1 -Random -ReportFormat HTML
```

---

## 🔢 Niveaux d'alerte détaillés

### Niveaux 1-2 : Événements informatifs (Informational)

![Level 1-2](https://img.shields.io/badge/Level_1%2D2-Informational-30A9DE)

| Action | Technique | Événement Windows |
|---|---|---|
| Démarrage d'application | EventLog custom | EventID 1000 |
| Login réussi simulé | Authentification | EventID 4624 (Type 2) |
| Arrêt d'application | EventLog custom | EventID 1001 |
| Création de fichier (FIM) | File Integrity Monitoring | FIM detection |
| Ouverture de session (Unlock) | Authentification | EventID 4624 (Type 7) |

### Niveau 3 : Événements système de bas niveau (Low)

![Level 3](https://img.shields.io/badge/Level_3-Low-yellow)

| Action | Technique | Cible |
|---|---|---|
| Modification de fichier surveillé | FIM Change Detection | Fichier de config |
| Modification permissions (ACL) | Audit ACL | Fichier de test |
| Changement de temps système | System Time Change | EventID 1 (System) |

### Niveau 4 : Événements système (System events)

![Level 4](https://img.shields.io/badge/Level_4-System-yellow)

| Action | Technique | Cible |
|---|---|---|
| Création de processus (audit) | Process Auditing | EventID 4688 |
| Changement politique d'audit | Audit Policy Change | EventID 4719 |
| Tâche planifiée | Scheduled Task | WazuhTestTask |
| Modification registre | Registry Monitoring | HKCU:\Software\WazuhTest |

### Niveau 5 : Événements utilisateur/système (User/System)

![Level 5](https://img.shields.io/badge/Level_5-User%2FSystem-yellow)

| Action | Technique | Événement Windows |
|---|---|---|
| Fermeture de session | Logoff Event | EventID 4647 |
| Échec attribution privilège | Privilege Assignment | EventID 4674 |
| Partage réseau | Network Share | EventID 5142 |
| Verrouillage de session | Workstation Lock | EventID 4800 |

### Niveaux 6-7 : Reconnaissance / Tentatives d'attaque (Reconnaissance)

![Level 6-7](https://img.shields.io/badge/Level_6%2D7-Reconnaissance-orange)

**Niveau 6 - Reconnaissance :**

| Action | Technique | Détails |
|---|---|---|
| Scan de ports local | Port Scanning | 14 ports : 22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017 |
| Requêtes DNS suspectes | DNS Query | 5 domaines : evil.com, malware.test, c2-server.invalid, suspicious.xyz.local, keylogger.fake |
| Fichiers suspects | Credential Files | `passw0rds.txt`, `credentials.bak` |

**Niveau 7 - Tentatives d'attaque :**

| Action | Technique | Détails |
|---|---|---|
| Brute force simulé | Failed Logins | 6 comptes : admin, root, administrator, sa, operator, manager (EventID 4625) |
| Accès chemins sensibles | Sensitive Path Access | SAM, SYSTEM, backdoor.exe, .ssh/id_rsa |
| Ping adresses externes | Network Recon | 8.8.8.8, 1.1.1.1, 10.10.10.10 |

### Niveau 8 : Attaques reconnues / Erreurs importantes

![Level 8](https://img.shields.io/badge/Level_8-Recognized_Attack-orange)

| Action | Technique | Détails |
|---|---|---|
| Injection de commandes | Command Injection | 5 patterns : `rm -rf`, `cmd.exe /c whoami`, `net user`, `$(whoami)`, XSS |
| Désactivation pare-feu | Firewall Disable | EventID 4950 |
| Modification ExecutionPolicy | PowerShell Policy | EventID 9999 |
| Téléchargement suspect | Suspicious Download | EventID 4104 (Invoke-WebRequest payload) |
| Lecture registre sécurité | Security Registry | EnableLUA, ConsentPromptBehaviorAdmin, SecureBootSettings |

### Niveau 9 : Attaques réussies / Violations de politique

![Level 9](https://img.shields.io/badge/Level_9-Policy_Violation-red)

| Action | Technique | Détails |
|---|---|---|
| Executable suspect dans TEMP | Malware Dropper | `svchost_update.exe` |
| Script PowerShell obfusqué | Obfuscation | XOR encoding + Invoke-Expression |
| Batch suspect | Discovery Commands | `net user`, `systeminfo`, `wmic` |
| Privilèges spéciaux assignés | Privilege Escalation | EventID 4672 (8 privilèges) |
| Tampering du fichier hosts | DNS Hijacking | Redirection google.com, facebook.com, microsoft.com |

### Niveau 10 : Attaques importantes (High severity)

![Level 10](https://img.shields.io/badge/Level_10-High_Severity-red)

| Action | Technique | Détails |
|---|---|---|
| Patterns Mimikatz | Credential Dumping | 7 commandes : `sekurlsa::logonpasswords`, `lsadump::sam`, `lsadump::dcsync`, `kerberos::list`, `privilege::debug`, `token::elevate`, `crypto::exportCertificates` |
| PsExec / Exécution distante | Lateral Movement | PSEXESVC.exe (EventID 4688) |
| Exécution WMI distante | WMI Abuse | wmiprvse.exe standalone |
| Persistence via Startup | Startup Persistence | `startup_persistence.bat` |
| Persistence via Run key | Registry Persistence | HKCU Run key |

### Niveau 11 : Attaques critiques / Malware (Critical)

![Level 11](https://img.shields.io/badge/Level_11-Critical-red)

| Action | Technique | Détails |
|---|---|---|
| Désactivation Windows Defender | AV Disable | EventID 5007 (DisableAntiSpyware) |
| Tâche SYSTEM avec EncodedCommand | Persistence | EventID 4698 (Base64 encoded) |
| DLL suspecte chargée | DLL Hijacking | C:\Temp\malicious.dll |
| Configuration système legacy | Legacy Config | winini_modif.ini, systemini_modif.ini |
| Pass-the-Hash simulé | Credential Replay | EventID 4624 Type 3 (NTLM, pas Kerberos) |

### Niveaux 12-13 : Événements critiques système / Rootkit

![Level 12-13](https://img.shields.io/badge/Level_12%2D13-Rootkit%2FCritical_System-darkred)

| Action | Technique | Niveau |
|---|---|---|
| Driver non signé | Rootkit Indicator | 12 |
| Debug kernel activé | Time Manipulation | 12 |
| Modification secteur de démarrage | MBR/VBR Tampering | 13 |
| Modification services critiques | Service Disabling | 13 (7 services : EventLog, WinDefend, SecurityCenter, wscsvc, mpssvc, BFE, MpsSvc) |
| Connexions ports C2 | C2 Communication | 13 (10 ports : 4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 6667, 6669) |
| Fichiers indicateurs rootkit | Rootkit Artifacts | 13 ($winnt$.dll, cmdvrt32.dll, expl0rer.exe, svchost_c.exe) |

### Niveaux 14-15 : Urgences / Intrusions confirmées (Emergency)

![Level 14-15](https://img.shields.io/badge/Level_14%2D15-Emergency-9B111E)

| Action | Technique | Niveau |
|---|---|---|
| Ransomware simulé | File Encryption | 14 (20 fichiers .encrypted) |
| Note de rançon | Ransom Note | 14 (README_DECRYPT.txt) |
| Suppression shadow copies | Anti-Forensics | 14 (vssadmin, WMI ShadowCopy) |
| Changement mot de passe admin | Credential Manipulation | 15 (EventID 4724) |
| Ajout utilisateur administrateur | Privilege Escalation | 15 (EventID 4732) |
| Reverse shell | Backdoor | 15 (powershell IEX DownloadString) |
| Nettoyage des logs | Anti-Forensics | 15 (EventID 1102 + 104) |

---

## ⚙️ Paramètres

```
PARAMÈTRES
    -Level <Int>              Niveau spécifique à exécuter (1-15). Par défaut : tous.
    -SkipDangerous            Ignore les niveaux 12-15 (actions potentiellement destructrices).
    -WhatIf                   Mode simulation : affiche les actions sans les exécuter.
    -Random                   Exécute 3 à 5 niveaux aléatoires.
    -Loop                     Mode continu : boucle infinie (Ctrl+C pour arrêter).
    -LoopInterval <Int>       Intervalle en secondes entre chaque itération en mode Loop (défaut: 30, min: 5, max: 3600).
    -ReportFormat <String>    Format du rapport : Console (défaut), JSON, ou HTML.
    -LogPath <String>         Chemin du répertoire de logs (défaut : $env:USERPROFILE\WazuhTestLogs).
    -NoCleanup                Ne pas nettoyer les artefacts de test à la fin.
```

---

## 📊 Rapports générés

Le script propose **3 formats de rapport** pour documenter vos sessions de test :

### Console (par défaut)

Affichage coloré en temps réel avec :
- Bannières de section par niveau
- Indicateurs visuels `[OK]`, `[FAIL]`, `[WARN]`, `[DEBUG]`
- Tableau récapitulatif par niveau avec statut
- Compteurs de succès/échec et durée totale

### JSON

Rapport structuré au format JSON contenant :
- Métadonnées (machine, utilisateur, date, durée, mode)
- Niveaux exécutés avec statut et commentaires
- Compteurs de succès/échec
- Chemin du fichier de log

Fichier généré : `%USERPROFILE%\WazuhTestLogs\<timestamp>_report.json`

### HTML

Dashboard visuel stylisé avec thème sombre contenant :
- Cartes de métriques (niveaux, succès, échecs, durée)
- Tableau détaillé par niveau avec codes couleur
- Grille de métadonnées (machine, utilisateur, mode, durée)
- Badge WhatIf si en mode simulation

Fichier généré : `%USERPROFILE%\WazuhTestLogs\<timestamp>_report.html`

---

## 🏗️ Architecture du script

```
Wazuh_Alert_Trigger_All_Levels.ps1
│
├── 0. Vérification des privilèges administrateur
│
├── 1. Configuration globale
│   ├── Répertoire de test (TEMP)
│   ├── Source d'événements personnalisée
│   ├── Compteurs de succès/échec
│   └── Configuration du logging
│
├── 2. Fonctions de logging
│   ├── Write-Log (fichier + console)
│   ├── Write-Banner / Write-Step
│   └── Write-Ok / Write-Warn / Write-Fail
│
├── 3. Fonctions helpers (avec support WhatIf)
│   ├── Write-CustomEventLog
│   ├── Create-TestFile / Remove-TestFile
│   ├── Test-PortConnection
│   ├── Invoke-TestDNS
│   └── Set-RegistryValue
│
├── 4. Suivi de progression (Write-Progress)
│
├── 5. Enregistrement des résultats (Register-LevelResult)
│
├── Niveaux d'alerte (Invoke-Level*)
│   ├── Invoke-Level1_2   (5 actions)
│   ├── Invoke-Level3      (3 actions)
│   ├── Invoke-Level4      (4 actions)
│   ├── Invoke-Level5      (4 actions)
│   ├── Invoke-Level6      (21 actions)
│   ├── Invoke-Level7      (14 actions)
│   ├── Invoke-Level8      (10 actions)
│   ├── Invoke-Level9      (5 actions)
│   ├── Invoke-Level10     (11 actions)
│   ├── Invoke-Level11     (6 actions)
│   ├── Invoke-Level12_13  (25 actions)
│   └── Invoke-Level14_15  (27 actions)
│
├── 6. Nettoyage (Invoke-Cleanup)
│   ├── Suppression fichiers de test
│   ├── Nettoyage registre
│   ├── Nettoyage tâches planifiées
│   └── Suppression source d'événements
│
├── 7. Rapports (Invoke-Report)
│   ├── Console (Write-ReportConsole)
│   ├── JSON (Write-ReportJSON)
│   └── HTML (Write-ReportHTML)
│
└── 8-9. Exécuteur & Main
    ├── Map des fonctions par niveau
    ├── Logique de sélection des niveaux
    ├── Boucle principale (support Loop)
    └── Gestion des erreurs (try/finally)
```

**Total : 100+ actions de test réparties sur 15 niveaux de sévérité**

---

## 🔒 Sécurité et nettoyage

### Nettoyage automatique

Le script nettoie automatiquement **tous les artefacts** générés pendant les tests :

- 📁 **Fichiers** : Suppression du répertoire temporaire `%TEMP%\Wazuh_Test_Artifacts`
- 🗄️ **Registre** : Suppression de `HKCU:\Software\WazuhTest` et des clés de persistance
- 📋 **Tâches planifiées** : Désenregistrement de `WazuhTestTask`
- 📊 **Source d'événements** : Suppression de la source `WazuhTestScript`

### Conservation des artefacts

Pour conserver les artefacts de test (par exemple pour un audit), utilisez le paramètre `-NoCleanup` :

```powershell
.\Wazuh_Alert_Trigger_All_Levels.ps1 -NoCleanup
```

### Logging persistant

Les logs détaillés sont conservés dans :
```
%USERPROFILE%\WazuhTestLogs\<YYYY-MM-DD_HH-mm-ss>.log
```

Chaque entrée est horodatée au millième de seconde avec un niveau de sévérité.

---

## 🤝 Contribuer

Les contributions sont les bienvenues ! Voici comment procéder :

1. **Fork** le projet
2. Créer une branche feature : `git checkout -b feature/ma-fonctionnalite`
3. Committer vos changements : `git commit -m 'Ajout de ma fonctionnalité'`
4. Pousser vers la branche : `git push origin feature/ma-fonctionnalite`
5. Ouvrir une **Pull Request**

---

## 📄 Licence

Ce projet est sous licence **MIT**. Consultez le fichier [LICENSE](LICENSE) pour plus de détails.

---

## 👤 Auteur

**DilaneNg**

[![GitHub](https://img.shields.io/badge/GitHub-DilaneNg-181717?style=for-the-badge&logo=GitHub)](https://github.com/DilaneNg)
[![Project](https://img.shields.io/badge/Repo-Wazuh__Alert__Trigger-181717?style=for-the-badge&logo=GitHub)](https://github.com/DilaneNg/Wazuh-Alert-Trigger-All-Levels)

---

<div align="center">

**Construit avec ❤️ pour la communauté cybersécurité**

[![Wazuh](https://img.shields.io/badge/Powered_by-Wazuh_SIEM-4CB848?style=for-the-badge&logo=Wazuh&logoColor=white)](https://wazuh.com/)
[![PowerShell](https://img.shields.io/badge/Written_in-PowerShell-5391FE?style=for-the-badge&logo=PowerShell&logoColor=white)](https://learn.microsoft.com/fr-fr/powershell/)

</div>