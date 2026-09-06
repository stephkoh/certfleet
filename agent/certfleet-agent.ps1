# ============================================================================
# certfleet - agent Windows
#
# Installe sur chaque serveur cible. Il fait trois choses, et rien d'autre :
#   1. s'enroler aupres du hub, en generant localement sa paire de cles RSA ;
#   2. signaler qu'il est vivant, avec son identite machine ;
#   3. venir chercher les certificats a poser, les dechiffrer, les installer
#      dans le magasin Windows ou sur le disque, et recharger le service.
#
# Communication SORTANTE uniquement, en HTTPS. Aucun port a ouvrir en entree.
# Le hub n'ouvre jamais de connexion vers ce serveur et ne detient aucun
# identifiant sur lui.
#
# La cle privee du certificat arrive chiffree et n'est dechiffrable QUE par cet
# agent : le hub chiffre avec la cle publique generee ici, et ne possede pas la
# cle privee correspondante.
#
# Config   : %ProgramData%\certfleet\agent.conf.json
# Etat     : %ProgramData%\certfleet\  (identifiant, jeton, cle RSA)
# Requiert : PowerShell 7 ou superieur
#
# PowerShell 5.1 est volontairement exclu : l'import d'une cle privee PKCS#8
# (ImportPkcs8PrivateKey) et l'association cle/certificat n'y existent pas, et
# les contourner demanderait de reimplementer l'ASN.1 a la main. PowerShell 7
# s'installe en une commande : winget install Microsoft.PowerShell
# ============================================================================
#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Position = 0)][string]$Action = "run")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$AgentVersion = "2.0.0"
$Dir          = Join-Path $env:ProgramData "certfleet"
$ConfFile     = Join-Path $Dir "agent.conf.json"
$TokenFile    = Join-Path $Dir "token"
$IdFile       = Join-Path $Dir "agent_id"
$KeyFile      = Join-Path $Dir "agent_key.pem"
$SelfPath     = Join-Path $Dir "certfleet-agent.ps1"

function Write-Log { param([string]$Message) Write-Host "[agent] $Message" }

# Mot de passe ephemere pour les exports PKCS#12. System.Web.Security n'existe
# pas dans .NET Core, donc pas dans PowerShell 7 : on tire les octets du
# generateur cryptographique. Ce mot de passe ne quitte jamais la fonction.
function New-EphemeralPassword {
  $bytes = [byte[]]::new(24)
  [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
  [Convert]::ToBase64String($bytes)
}

# Convertit une chaine hexadecimale en octets. L'IV arrive du hub sous cette
# forme ; un decoupage naif laisserait une chaine vide en fin de tableau.
function ConvertFrom-HexString {
  param([string]$Hex)
  $bytes = [byte[]]::new($Hex.Length / 2)
  for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
  }
  ,$bytes
}

New-Item -ItemType Directory -Force -Path $Dir | Out-Null

# ── Configuration ───────────────────────────────────────────────────────────
if (-not (Test-Path $ConfFile)) { throw "Configuration absente : $ConfFile" }
$Conf = Get-Content $ConfFile -Raw | ConvertFrom-Json
$Hub  = ($Conf.CertfleetUrl).TrimEnd("/")
if (-not $Hub) { throw "CertfleetUrl absent de $ConfFile" }

# ── Identite stable ─────────────────────────────────────────────────────────
# Derivee du GUID machine : elle survit a un changement de nom d'hote, ce qui
# evite de creer un doublon dans l'inventaire du hub.
if (-not (Test-Path $IdFile)) {
  $guid = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid -ErrorAction SilentlyContinue).MachineGuid
  if (-not $guid) { $guid = [guid]::NewGuid().ToString() }
  "$($env:COMPUTERNAME.ToLower())-$($guid.Replace('-','').Substring(0,12))" |
    Set-Content -Path $IdFile -Encoding ascii -NoNewline
}
$AgentId = (Get-Content $IdFile -Raw).Trim()

# ── Cle de l'agent ──────────────────────────────────────────────────────────
# Generee ici, elle ne quitte jamais la machine. Seule la partie publique part
# vers le hub, a l'enrolement.
function Get-AgentKey {
  if (Test-Path $KeyFile) {
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportFromPem((Get-Content $KeyFile -Raw))
    return $rsa
  }
  $rsa = [System.Security.Cryptography.RSA]::Create(2048)
  $pem = $rsa.ExportPkcs8PrivateKeyPem()
  Set-Content -Path $KeyFile -Value $pem -Encoding ascii
  # La cle privee ne doit etre lisible que par SYSTEM et les administrateurs.
  icacls $KeyFile /inheritance:r /grant "SYSTEM:F" /grant "Administrators:F" | Out-Null
  Write-Log "paire de cles RSA generee"
  return $rsa
}

# ── Identite machine, envoyee au hub ────────────────────────────────────────
function Get-MachineInfo {
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue

  # Adresse par laquelle la machine sort : plus parlante que la liste complete
  # des interfaces. Aucun paquet n'est reellement emis.
  $ip = ""
  try {
    $ip = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } |
           Select-Object -First 1).IPv4Address.IPAddress
  } catch { }

  [ordered]@{
    agent_id      = $AgentId
    agent_version = $AgentVersion
    platform      = "windows"
    hostname      = $env:COMPUTERNAME.ToLower()
    fqdn          = [System.Net.Dns]::GetHostEntry("").HostName
    ip            = $ip
    os            = if ($os) { $os.Caption } else { "Windows" }
    os_version    = if ($os) { $os.Version } else { "" }
    kernel        = if ($os) { $os.BuildNumber } else { "" }
    arch          = $env:PROCESSOR_ARCHITECTURE
    sudo_mode     = "administrator"
  }
}

function Invoke-Hub {
  param([string]$Path, [string]$Method = "GET", $Body = $null)
  $headers = @{ "Content-Type" = "application/json" }
  if (Test-Path $TokenFile) { $headers["X-Agent-Token"] = (Get-Content $TokenFile -Raw).Trim() }
  # $args est une variable automatique : on nomme la notre autrement.
  $req = @{ Uri = "$Hub$Path"; Method = $Method; Headers = $headers; UseBasicParsing = $true; TimeoutSec = 30 }
  if ($Body) { $req["Body"] = ($Body | ConvertTo-Json -Depth 6 -Compress) }
  Invoke-RestMethod @req
}

# ── Enrolement ──────────────────────────────────────────────────────────────
function Invoke-Enroll {
  $enrollToken = $Conf.EnrollToken
  if (-not $enrollToken) { throw "EnrollToken absent de $ConfFile" }

  $rsa  = Get-AgentKey
  $body = Get-MachineInfo
  $body["enroll_token"] = $enrollToken
  $body["pubkey"]       = $rsa.ExportSubjectPublicKeyInfoPem()

  $resp = Invoke-RestMethod -Uri "$Hub/api/agents/enroll" -Method POST `
            -ContentType "application/json" -TimeoutSec 30 `
            -Body ($body | ConvertTo-Json -Depth 6 -Compress)

  if (-not $resp.token) { throw "le hub n'a pas renvoye de jeton" }
  Set-Content -Path $TokenFile -Value $resp.token -Encoding ascii -NoNewline
  icacls $TokenFile /inheritance:r /grant "SYSTEM:F" /grant "Administrators:F" | Out-Null
  Write-Log "enrole aupres de $Hub sous l'identifiant $AgentId"
}

# ── Signal de vie ───────────────────────────────────────────────────────────
function Invoke-Heartbeat {
  if (-not (Test-Path $TokenFile)) { Write-Log "pas encore enrole"; return }
  try {
    Invoke-Hub -Path "/api/agents/heartbeat" -Method POST -Body (Get-MachineInfo) | Out-Null
    Write-Log "signal de vie transmis"
  } catch {
    Write-Log "signal de vie : $($_.Exception.Message)"
  }
}

# ── Compte rendu d'execution ────────────────────────────────────────────────
function Send-Result {
  param([int]$Id, [int]$Code, [string]$Output)
  try {
    Invoke-Hub -Path "/api/agents/command-result" -Method POST -Body @{
      agent_id = $AgentId; command_id = $Id; exit_code = $Code
      result = $Output.Substring(0, [Math]::Min(9000, $Output.Length))
    } | Out-Null
  } catch { }
  Write-Log "commande #$Id terminee (code $Code)"
}

# ── Dechiffrement du payload ────────────────────────────────────────────────
# Chiffrement hybride :
#   aeskey_enc = RSA-OAEP-SHA256(cle AES 32 o, cle publique de CET agent)
#   key_cipher = AES-256-CBC(cle privee PEM)
function Unprotect-PrivateKey {
  param($Payload)
  $rsa    = Get-AgentKey
  $aesKey = $rsa.Decrypt([Convert]::FromBase64String($Payload.aeskey_enc),
                         [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)

  $aes = [System.Security.Cryptography.Aes]::Create()
  $aes.Key = $aesKey
  $aes.IV  = ConvertFrom-HexString $Payload.key_iv
  $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
  $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

  $cipher = [Convert]::FromBase64String($Payload.key_cipher)
  $plain  = $aes.CreateDecryptor().TransformFinalBlock($cipher, 0, $cipher.Length)
  [System.Text.Encoding]::UTF8.GetString($plain)
}

# ── Construction du PFX ─────────────────────────────────────────────────────
# Windows range les certificats dans un magasin, pas dans des fichiers : il
# faut donc reassembler certificat + cle privee en un objet PKCS#12.
function New-CertificateFromPem {
  param([string]$CertPem, [string]$KeyPem)

  $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem(
            $CertPem, $KeyPem)

  # Sans ce reexport, la cle privee n'est pas persistee et le certificat serait
  # inutilisable apres redemarrage : il faut repasser par un PFX.
  $pwd = New-EphemeralPassword
  $pfx = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pwd)

  [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $pfx, $pwd,
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
}

function Install-InStore {
  param($Certificate, [string]$StoreName = "My", [string]$FriendlyName = "")
  $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
             $StoreName, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  # Nom convivial : sans lui, le certificat n'est identifiable que par son
  # empreinte dans la console de gestion Windows.
  if ($FriendlyName) { try { $Certificate.FriendlyName = "certfleet - $FriendlyName" } catch { } }
  $store.Add($Certificate)
  $store.Close()
  "installe dans LocalMachine\$StoreName (empreinte $($Certificate.Thumbprint))"
}

# ── Liaison au service ──────────────────────────────────────────────────────
function Set-IisBinding {
  param($Certificate, $Params)
  Import-Module WebAdministration -ErrorAction Stop

  $site    = if ($Params.PSObject.Properties['site']) { $Params.site } else { "Default Web Site" }
  $binding = if ($Params.PSObject.Properties['binding']) { $Params.binding } else { "https :443:" }
  $store   = if ($Params.PSObject.Properties['store']) { $Params.store } else { "My" }

  # Format attendu : "https <ip>:<port>:<en-tete d'hote>", champs vides admis.
  $parts = $binding -split '\s+', 2
  $spec  = if ($parts.Count -gt 1) { $parts[1] } else { ":443:" }
  $f     = $spec -split ':', 3
  $ip    = if ($f[0]) { $f[0] } else { "*" }
  $port  = if ($f.Count -gt 1 -and $f[1]) { $f[1] } else { "443" }
  # $host est une variable automatique en lecture seule : on ne l'utilise pas.
  $hostHeader = if ($f.Count -gt 2) { $f[2] } else { "" }

  $existing = Get-WebBinding -Name $site -Protocol https -Port $port -ErrorAction SilentlyContinue
  if (-not $existing) {
    New-WebBinding -Name $site -Protocol https -IPAddress $ip -Port $port -HostHeader $hostHeader `
      -SslFlags $(if ($hostHeader) { 1 } else { 0 }) | Out-Null
  }

  # Rebinding : on remplace l'ancien certificat par le nouveau sur ce port.
  $b = Get-WebBinding -Name $site -Protocol https -Port $port
  $b.AddSslCertificate($Certificate.Thumbprint, $store) | Out-Null
  "IIS : site '$site' lie sur $ip`:$port$(if ($hostHeader) { " (hote $hostHeader)" })"
}

function Set-ExchangeServices {
  param($Certificate, $Params)
  # Exchange expose ses applets via un composant logiciel enfichable, absent
  # d'une session PowerShell ordinaire.
  if (-not (Get-Command Enable-ExchangeCertificate -ErrorAction SilentlyContinue)) {
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
  }
  $services = if ($Params.PSObject.Properties['services']) { $Params.services } else { "IIS,SMTP" }
  Enable-ExchangeCertificate -Thumbprint $Certificate.Thumbprint -Services $services -Force
  "Exchange : services $services actives sur l'empreinte $($Certificate.Thumbprint)"
}

function Set-RdsCertificate {
  param($Certificate, $Params)
  $deployment = if ($Params.PSObject.Properties['deployment']) { $Params.deployment } else { "standalone" }

  if ($deployment -eq "rds-deployment") {
    Import-Module RemoteDesktop -ErrorAction Stop
    $broker = $Params.connection_broker
    $pwd = New-EphemeralPassword
    $tmp = Join-Path $env:TEMP "certfleet-rds.pfx"
    [IO.File]::WriteAllBytes($tmp, $Certificate.Export(
      [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pwd))
    try {
      foreach ($role in @("RDGateway", "RDWebAccess", "RDRedirector", "RDPublishing")) {
        Set-RDCertificate -Role $role -ImportPath $tmp `
          -Password (ConvertTo-SecureString $pwd -AsPlainText -Force) `
          -ConnectionBroker $broker -Force
      }
    } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    "RDS : certificat applique aux quatre roles du deploiement"
  } else {
    # Passerelle autonome : la liaison se fait par le fournisseur WMI de RD Gateway.
    $gw = Get-CimInstance -Namespace "root\CIMV2\TerminalServices" -ClassName Win32_TSGatewayServerSettings
    Invoke-CimMethod -InputObject $gw -MethodName SetCertificate `
      -Arguments @{ CertHash = $Certificate.Thumbprint } | Out-Null
    "RD Gateway : certificat applique (empreinte $($Certificate.Thumbprint))"
  }
}

# ── Pose d'un certificat ────────────────────────────────────────────────────
function Invoke-DeployCert {
  param([int]$Id, $Payload)
  $out = ""; $code = 0

  try {
    $keyPem  = Unprotect-PrivateKey -Payload $Payload
    $certPem = $Payload.cert_pem
    $params  = if ($Payload.PSObject.Properties['params']) { $Payload.params } else { [pscustomobject]@{} }
    $type    = if ($Payload.PSObject.Properties['target_type']) { $Payload.target_type } else { "" }
    $mode    = if ($Payload.PSObject.Properties['mode']) { $Payload.mode } else { "file" }

    if ($mode -eq "store") {
      $cert = New-CertificateFromPem -CertPem $certPem -KeyPem $keyPem
      $storeName = if ($params.PSObject.Properties['store']) { $params.store } else { "My" }
      $cn = if ($Payload.PSObject.Properties['common_name']) { $Payload.common_name } else { "" }
      $out = Install-InStore -Certificate $cert -StoreName $storeName -FriendlyName $cn

      switch ($type) {
        "iis"         { $out += " | " + (Set-IisBinding      -Certificate $cert -Params $params) }
        "exchange"    { $out += " | " + (Set-ExchangeServices -Certificate $cert -Params $params) }
        "rds_gateway" { $out += " | " + (Set-RdsCertificate   -Certificate $cert -Params $params) }
        default       { $out += " | aucune liaison de service pour le type '$type'" }
      }
    }
    else {
      # Mode fichier : Serv-U, keystores et applications qui lisent des PEM.
      $certPath = $Payload.cert_path
      $keyPath  = $Payload.key_path
      if (-not $certPath -or -not $keyPath) { throw "chemins manquants dans le payload" }

      foreach ($p in @($certPath, $keyPath)) {
        $d = Split-Path $p -Parent
        if ($d -and -not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
      }

      # HAProxy et assimiles attendent un seul fichier : le hub le signale en
      # donnant le meme chemin pour le certificat et la cle.
      if ($certPath -eq $keyPath) {
        Set-Content -Path $certPath -Value ($certPem + "`n" + $keyPem) -Encoding ascii
      } else {
        Set-Content -Path $certPath -Value $certPem -Encoding ascii
        Set-Content -Path $keyPath  -Value $keyPem  -Encoding ascii
        icacls $keyPath /inheritance:r /grant "SYSTEM:F" /grant "Administrators:F" | Out-Null
      }

      $out = "ecrit : $certPath"
      if ($Payload.PSObject.Properties['chain_path'] -and $Payload.chain_path) {
        Set-Content -Path $Payload.chain_path -Value $Payload.chain_pem -Encoding ascii
        $out += " | chaine : $($Payload.chain_path)"
      }
    }

    # Rechargement du service, si la cible en demande un.
    if ($Payload.PSObject.Properties['reload_cmd'] -and $Payload.reload_cmd) {
      try {
        $r = Invoke-Expression $Payload.reload_cmd 2>&1 | Out-String
        $out += " | rechargement : " + $r.Trim()
      } catch {
        $out += " | RECHARGEMENT EN ECHEC : $($_.Exception.Message)"
        $code = 1
      }
    }
  }
  catch {
    $out = $_.Exception.Message
    $code = 1
  }

  Send-Result -Id $Id -Code $code -Output $out
}

# ── File de commandes ───────────────────────────────────────────────────────
# Un agent certfleet n'execute qu'un seul type de commande : poser un
# certificat. Tout le reste est refuse, meme si le hub le demandait.
function Invoke-Poll {
  if (-not (Test-Path $TokenFile)) { return }
  $token = (Get-Content $TokenFile -Raw).Trim()
  try {
    $cmds = Invoke-Hub -Path "/api/agents/commands?agent_id=$AgentId&token=$([uri]::EscapeDataString($token))"
  } catch { Write-Log "file inaccessible : $($_.Exception.Message)"; return }

  foreach ($c in @($cmds)) {
    if (-not $c) { continue }
    if ($c.kind -eq "cert") { Invoke-DeployCert -Id $c.id -Payload $c.payload }
    else { Send-Result -Id $c.id -Code 1 -Output "type de commande refuse par l'agent : $($c.kind)" }
  }
}

# ── Mise a jour automatique ─────────────────────────────────────────────────
# Le script n'est remplace que s'il s'analyse correctement : une version
# tronquee par une coupure reseau ne doit pas casser l'agent en place.
function Update-Self {
  if ($Conf.PSObject.Properties['AutoUpdate'] -and -not $Conf.AutoUpdate) { return }
  try {
    $tmp = Join-Path $env:TEMP "certfleet-agent.new.ps1"
    Invoke-WebRequest -Uri "$Hub/api/agents/agent.ps1" -OutFile $tmp -UseBasicParsing -TimeoutSec 20
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$null, [ref]$errors) | Out-Null
    if ($errors.Count -eq 0 -and
        (Get-FileHash $tmp).Hash -ne (Get-FileHash $SelfPath).Hash) {
      Copy-Item $tmp $SelfPath -Force
      Write-Log "mise a jour appliquee"
      & $SelfPath run
      exit 0
    }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  } catch { }
}

# ── Installation de la tache planifiee ──────────────────────────────────────
function Install-Task {
  $action  = New-ScheduledTaskAction -Execute "pwsh.exe" `
               -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$SelfPath`" run"
  # Le decalage aleatoire evite qu'un parc entier interroge le hub a la meme
  # seconde apres un redemarrage groupe.
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
               -RepetitionInterval (New-TimeSpan -Minutes 5)
  $trigger.RandomDelay = "PT60S"
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd `
                 -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

  Register-ScheduledTask -TaskName "certfleet-agent" -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
  Write-Log "tache planifiee active - interrogation toutes les 5 minutes"
}

# ── Point d'entree ──────────────────────────────────────────────────────────
switch ($Action.ToLower()) {
  "enroll"  { Invoke-Enroll }
  "beat"    { Invoke-Heartbeat }
  "poll"    { Invoke-Poll }
  "install" { Install-Task }
  "version" { Write-Host "certfleet-agent $AgentVersion (windows)" }
  "run"     { Update-Self; Invoke-Heartbeat; Invoke-Poll }
  default   { Write-Host "usage: certfleet-agent.ps1 {run|enroll|beat|poll|install|version}"; exit 1 }
}
