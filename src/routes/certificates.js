// ════════════════════════════════════════════════════════════════════
// routes/certificates.js — inventaire, émission ACME, déploiement, supervision.
//
// Un certificat porte N domaines, se déploie sur N cibles et se vérifie sur N
// points de terminaison. La sonde TLS ne lit jamais la base : elle rouvre une
// vraie connexion et compare l'empreinte réellement servie, ce qui met en
// évidence le cas classique du certificat écrit sur disque mais jamais rechargé.
//
// Tables : cert_certificates / cert_domains / cert_targets / cert_endpoints /
//          cert_deployments, créées par ensureCertSchema().
// ════════════════════════════════════════════════════════════════════
import express from "express";
import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import { query } from "../db.js";
import { requireRole, audit } from "../auth.js";
import { probeTls, expiryStatus, TLS_KINDS } from "../lib/certprobe.js";
import { issueCertificate, ACME_DIRECTORIES, resolveChallengeTarget } from "../lib/acme.js";
import { gandiFindZone, gandiUpsertTxt, gandiDeleteTxt } from "../lib/dns/gandi.js";
import { vaultEncrypt, vaultDecrypt } from "../lib/vault.js";

const router = express.Router();

// ── Contrôle d'accès du module ───────────────────────────────────────
// Lecture ouverte à tout compte authentifié ; toute écriture — émettre,
// déployer, supprimer — exige au moins le rôle « operator ». Le rôle
// « viewer » peut donc consulter l'état du parc sans pouvoir y toucher.
// Le téléchargement de la clé privée porte sa propre garde (administrateur).
router.use((req, res, next) => {
  if (req.method === "GET") return next();
  return requireRole("operator")(req, res, next);
});

// Journalise toute écriture : qui a émis, déployé, supprimé, et avec quel
// résultat. Écrit après coup pour connaître le code de retour.
router.use((req, res, next) => {
  if (req.method === "GET") return next();
  res.on("finish", () => {
    audit(req, `cert.${req.method.toLowerCase()}`, {
      target: req.originalUrl.replace(/^\/api\/certificates/, "") || "/",
      ok: res.statusCode < 400,
      detail: { status: res.statusCode },
    });
  });
  next();
});

// ── Catalogue des types de cible + schéma de paramètres (sert l'UI de settings) ──
// mode : 'agent' (l'agent installé sur la cible pose le certificat)
//      | 'api'   (le hub appelle directement l'API de l'appliance)
//      | 'k8s'   (surveillance seule : cert-manager reste maître)
export const TARGET_TYPES = [
  { type: "k8s_secret",   label: "Kubernetes (Secret TLS)", mode: "api",   icon: "\u2638\uFE0F",
    note: "Écrit le Secret TLS dans le cluster via l'API, et redémarre au besoin ce qui monte le certificat. Sur un cluster où cert-manager gère déjà l'émission, laissez-le faire : ce connecteur sert aux certificats émis À L'EXTÉRIEUR du cluster.",
    fields: [ { key: "cluster", label: "Nom du cluster (libellé)", type: "text", required: true },
              { key: "api_url", label: "URL de l'API Kubernetes", type: "text", required: true, placeholder: "https://10.0.0.1:6443" },
              { key: "token", label: "Jeton du ServiceAccount", type: "password", required: true },
              { key: "ca_cert_pem", label: "Certificat de l'autorité du cluster (PEM)", type: "text" },
              { key: "insecure", label: "Ne pas vérifier le certificat de l'API", type: "bool" },
              { key: "namespace", label: "Namespace", type: "text", required: true },
              { key: "secret", label: "Nom du Secret TLS", type: "text", required: true },
              { key: "restart", label: "Redémarrages après pose", type: "text", placeholder: "deployment/front,statefulset/api" } ] },
  { type: "nginx",        label: "nginx", mode: "agent", os: "linux", icon: "🌐",
    note: "reload (jamais restart). fullchain + clé.",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin fullchain", type: "text", required: true, placeholder: "/etc/nginx/ssl/site.crt" },
              { key: "key_path", label: "Chemin clé", type: "text", required: true, placeholder: "/etc/nginx/ssl/site.key" },
              { key: "reload_cmd", label: "Commande reload", type: "text", default: "nginx -s reload" } ] },
  { type: "apache",       label: "Apache", mode: "agent", os: "both", icon: "🪶",
    note: "reload (jamais restart).",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin cert", type: "text", required: true },
              { key: "key_path", label: "Chemin clé", type: "text", required: true },
              { key: "chain_path", label: "Chemin chaîne", type: "text" },
              { key: "reload_cmd", label: "Commande reload", type: "text", default: "apachectl graceful" } ] },
  { type: "haproxy",      label: "HAProxy", mode: "agent", os: "linux", icon: "🔀",
    note: "fullchain + clé CONCATÉNÉS dans un seul PEM.",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "pem_path", label: "Chemin PEM combiné", type: "text", required: true, placeholder: "/etc/haproxy/certs/site.pem" },
              { key: "reload_cmd", label: "Commande reload", type: "text", default: "systemctl reload haproxy" },
              { key: "ha_role", label: "Rôle dans la paire HA", type: "select",
                options: [["", "— nœud isolé —"], ["backup", "Backup (déployé en premier)"], ["master", "Master (après le délai)"]] },
              { key: "ha_delay_min", label: "Délai avant le master (minutes)", type: "text", default: "10" } ] },
  { type: "aloha",        label: "HAProxy ALOHA (appliance virtuelle)", mode: "api", icon: "🔀",
    note: "Seul connecteur API implémenté à ce jour, et éprouvé en production. Mise à jour à chaud, sans redémarrage de l'appliance.",
    fields: [ { key: "base_url", label: "URL Data Plane API", type: "text", required: true, placeholder: "http://lb-01.example.com:5555" },
              { key: "cert_name", label: "Nom du fichier certificat (storage ALOHA)", type: "text", required: true, placeholder: "exampleservicescom.pem" },
              { key: "username", label: "Utilisateur API (Basic Auth)", type: "text", required: true, placeholder: "admin" },
              { key: "password", label: "Mot de passe API", type: "password", required: true },
              { key: "insecure", label: "Ignorer la vérif TLS (API en HTTPS auto-signé)", type: "bool" },
              { key: "ha_role", label: "Rôle dans la paire HA", type: "select",
                options: [["", "— nœud isolé —"], ["backup", "Backup (déployé en premier)"], ["master", "Master (après le délai)"]] },
              { key: "ha_delay_min", label: "Délai avant le master (minutes)", type: "text", default: "10" } ] },
  { type: "caddy",        label: "Caddy", mode: "agent", os: "both", icon: "🧱",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin cert", type: "text", required: true },
              { key: "key_path", label: "Chemin clé", type: "text", required: true },
              { key: "reload_cmd", label: "Commande reload", type: "text", default: "caddy reload" } ] },
  { type: "traefik",      label: "Traefik (fichier)", mode: "agent", os: "both", icon: "🚦",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin cert", type: "text", required: true },
              { key: "key_path", label: "Chemin clé", type: "text", required: true } ] },
  { type: "glpi",         label: "GLPI (serveur web)", mode: "agent", os: "linux", icon: "🧰",
    note: "GLPI = appli web PHP servie par Apache/nginx : on dépose le cert sur le serveur web + reload.",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin du certificat (vhost)", type: "text", required: true, placeholder: "/etc/pki/tls/certs/glpi.crt" },
              { key: "key_path", label: "Chemin de la clé (vhost)", type: "text", required: true, placeholder: "/etc/pki/tls/private/glpi.key" },
              { key: "reload_cmd", label: "Reload serveur web", type: "text", default: "systemctl reload httpd" } ] },
  { type: "vsftpd",       label: "vsftpd", mode: "agent", os: "linux", icon: "📁",
    note: "vsftpd : rsa_cert_file + rsa_private_key_file (2 fichiers séparés) + restart.",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin du certificat (rsa_cert_file)", type: "text", required: true, placeholder: "/etc/ssl/certs/vsftpd.pem" },
              { key: "key_path", label: "Chemin de la clé (rsa_private_key_file)", type: "text", required: true, placeholder: "/etc/ssl/private/vsftpd.key" },
              { key: "reload_cmd", label: "Commande", type: "text", default: "systemctl restart vsftpd" } ] },
  { type: "servu",        label: "Serv-U (FTP)", mode: "agent", os: "both", icon: "📂",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin cert (.crt)", type: "text", required: true },
              { key: "key_path", label: "Chemin clé (.key)", type: "text", required: true },
              { key: "chain_path", label: "Chemin chaîne / CA (.pem)", type: "text", placeholder: "/usr/local/Serv-U/pki/2025/letsencrypt-chain.pem" } ] },
  { type: "iis",          label: "IIS (Windows)", mode: "agent", os: "windows", icon: "🪟",
    note: "Rebind par thumbprint + nettoyage du store (sinon il gonfle).",
    fields: [ { key: "agent_id", label: "Agent Windows", type: "agent", required: true },
              { key: "site", label: "Site IIS", type: "text", required: true, placeholder: "Default Web Site" },
              { key: "binding", label: "Binding", type: "text", default: "https :443:" },
              { key: "store", label: "Store", type: "text", default: "My" } ] },
  { type: "exchange",     label: "Exchange", mode: "agent", os: "windows", icon: "📧",
    note: "Enable-ExchangeCertificate -Services IIS,SMTP,IMAP,POP -Force. Receive Connectors : TlsCertificateName au format <I>issuer<S>subject (JAMAIS le thumbprint). Purger les anciens.",
    fields: [ { key: "agent_id", label: "Agent Windows", type: "agent", required: true },
              { key: "services", label: "Services", type: "text", default: "IIS,SMTP,IMAP,POP" },
              { key: "update_receive_connectors", label: "MAJ Receive Connectors (TlsCertificateName)", type: "bool", default: true },
              { key: "purge_old", label: "Purger les anciens certs", type: "bool", default: true } ] },
  { type: "rds_gateway",  label: "Passerelle RDS (RD Gateway)", mode: "agent", os: "windows", icon: "🪟",
    note: "Windows : PFX importé dans LocalMachine\\My + lié au rôle RD Gateway. Agent Windows requis.",
    fields: [ { key: "agent_id", label: "Agent Windows", type: "agent", required: true },
              { key: "deployment", label: "Type (standalone | rds-deployment)", type: "text", default: "standalone" },
              { key: "connection_broker", label: "Connection Broker (si rds-deployment)", type: "text" },
              { key: "pfx_password_ref", label: "Réf. mot de passe PFX (secret, optionnel)", type: "text" } ] },
  { type: "java_keystore", label: "Java Keystore (PKCS12)", mode: "agent", os: "both", icon: "☕",
    note: "Alias + redémarrage applicatif quasi toujours nécessaire.",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "keystore_path", label: "Chemin keystore", type: "text", required: true },
              { key: "alias", label: "Alias", type: "text", required: true },
              { key: "storepass", label: "Mot de passe du keystore", type: "password", required: true },
              { key: "restart_cmd", label: "Commande restart appli", type: "text" } ] },
  { type: "uag",          label: "VMware Horizon / UAG", mode: "api", icon: "🖥️",
    note: "Unified Access Gateway (VDI) — connecteur API REST à cadrer.",
    fields: [ { key: "base_url", label: "URL admin UAG", type: "text", required: true, placeholder: "https://uag:9443" },
              { key: "cred_ref", label: "Réf. identifiants (secret)", type: "text", required: true } ] },
  { type: "f5",           label: "F5 BIG-IP", mode: "api", icon: "🅵",
    fields: [ { key: "base_url", label: "URL iControl REST", type: "text", required: true },
              { key: "profile", label: "Client SSL profile", type: "text" },
              { key: "cred_ref", label: "Réf. identifiants (secret)", type: "text", required: true } ] },
  { type: "checkpoint",   label: "Check Point", mode: "api", icon: "🛡️",
    fields: [ { key: "base_url", label: "URL API", type: "text", required: true },
              { key: "cred_ref", label: "Réf. identifiants (secret)", type: "text", required: true } ] },
  { type: "api_generic",  label: "Appliance générique (API)", mode: "api", icon: "🔌",
    note: "Appliances/API sans agent : ECS Dell, Harbor, F5, Check Point… (Zabbix/Graylog/NetBox = via agent, cible Apache/nginx)",
    fields: [ { key: "base_url", label: "URL API", type: "text", required: true },
              { key: "method", label: "Méthode d'upload", type: "text", default: "PUT" },
              { key: "cred_ref", label: "Réf. identifiants (secret)", type: "text" } ] },
];

// ── Guides détaillés par type (niveau débutant) — affichés à la sélection du type ──
const AGENT_PREP = [
  "Sur le serveur CIBLE, installez l'agent : ouvrez l'onglet Agents, copiez la commande d'installation et exécutez-la en root. Elle pose l'agent, le helper de certificat, la règle sudoers et la minuterie d'un seul coup — rien à installer à la main.",
  "Attendez une minute, puis vérifiez que le serveur apparaît dans l'onglet Agents avec un contact récent. Il sera alors proposé dans la liste déroulante « Agent » ci-dessus, sous son nom d'hôte.",
  "Le déploiement est entièrement non interactif : le helper s'exécute en NOPASSWD et aucun mot de passe n'est jamais demandé, y compris lors d'un renouvellement nocturne. C'est le helper qui recharge le service, en root, sur une liste blanche interne de commandes.",
  "Dépannage seulement, si l'agent est en place mais que le helper manque : les commandes manuelles sont dans l'onglet « Types de cible », encadré « Prérequis d'une cible agent ». Sans le helper, l'agent écrit bien le certificat mais ne recharge pas le service — et il le dit dans son compte rendu.",
];
const TARGET_GUIDES = {
  nginx: { what: "Dépose le certificat (fullchain) + la clé privée sur un serveur nginx, puis recharge nginx (sans coupure).",
    prepare: AGENT_PREP,
    fields: { agent_id: "Le serveur nginx (par hostname).",
      cert_path: "Chemin pointé par « ssl_certificate » dans la conf nginx. Ex : /etc/nginx/ssl/monsite.crt",
      key_path: "Chemin pointé par « ssl_certificate_key ». Ex : /etc/nginx/ssl/monsite.key",
      reload_cmd: "nginx recharge à chaud, JAMAIS restart : nginx -s reload (ou systemctl reload nginx)" },
    verify: "openssl s_client -connect monsite:443 -servername monsite | openssl x509 -noout -dates  → dates du cert servi.",
    gotcha: "Les chemins doivent correspondre EXACTEMENT à ssl_certificate / ssl_certificate_key de la conf. nginx veut le fullchain (leaf+intermédiaires) — c'est ce que certfleet fournit." },
  apache: { what: "Dépose cert + chaîne + clé sur Apache (httpd) et recharge (graceful).",
    prepare: AGENT_PREP,
    fields: { agent_id: "Le serveur Apache.",
      cert_path: "SSLCertificateFile. Ex : /etc/pki/tls/certs/monsite.crt",
      key_path: "SSLCertificateKeyFile. Ex : /etc/pki/tls/private/monsite.key",
      reload_cmd: "apachectl graceful — recharge sans couper les connexions établies. systemctl reload httpd fait la même chose." },
    verify: "curl -vI https://monsite  → regarde la date d'expiration.",
    gotcha: "Depuis Apache 2.4.8, SSLCertificateFile accepte la chaîne complète (feuille puis intermédiaires) et SSLCertificateChainFile est obsolète : ne renseignez le chemin de chaîne que pour un Apache antérieur, sinon la directive sera refusée au démarrage." },
  haproxy: { what: "Dépose UN SEUL fichier PEM contenant fullchain + clé concaténés, puis recharge HAProxy.",
    prepare: AGENT_PREP,
    fields: { agent_id: "Le serveur HAProxy.",
      pem_path: "Fichier PEM unique référencé par « bind … ssl crt <ici> ». Ex : /etc/haproxy/certs/monsite.pem. certfleet y met fullchain + clé ensemble.",
      reload_cmd: "systemctl reload haproxy (reload = pas de coupure)" },
    verify: "echo | openssl s_client -connect monsite:443 2>/dev/null | openssl x509 -noout -enddate",
    gotcha: "HAProxy exige fullchain ET clé dans le MÊME fichier .pem — certfleet gère cette concaténation. Le dossier crt peut contenir plusieurs .pem (SNI)." },
  aloha: { what: "HAProxy ALOHA est une APPLIANCE load-balancer : certfleet pousse le PEM combiné (fullchain + clé) via la Data Plane API (DPAPI), qui REMPLACE à chaud le certificat existant dans le storage ALOHA (/etc/ssl/frontends/<nom>/). Aucun agent installable dessus. ✅ Connecteur opérationnel.",
    prepare: [
      "COMPTE API : l'auth Basic de la DPAPI se fait contre les utilisateurs SYSTÈME de l'appliance. Se connecter EN SSH à l'ALOHA (pas la GUI web) et créer un compte dédié : `ssh admin@<aloha>` puis `sudo useradd -M -s /sbin/nologin srv_certfleet` et `sudo passwd srv_certfleet`. (Alternative : définir l'utilisateur dans /app/management/var/lib/dataplaneapi/dataplaneapi.yaml puis redémarrer le service dataplaneapi via l'onglet Services de la GUI.)",
      "Vérifier l'accès API (port 5555 par défaut, base /v3) : `curl -u srv_certfleet:<pass> http://<aloha>:5555/v3/info` doit répondre 200.",
      "Repérer le NOM EXACT du fichier certificat dans le storage : bouton « 🔎 Tester & lister » dans le formulaire de cible (appelle GET /v3/services/haproxy/storage/ssl_certificates). C'est ce nom (ex. exampleservicescom.pem) qui va dans « cert_name ».",
    ],
    fields: {
      base_url: "URL de la Data Plane API. Ex : http://lb-01.example.com:5555 (5555=HTTP par défaut ; 6443 si HTTPS activé).",
      cert_name: "Nom du fichier certificat dans le storage ALOHA (tel que listé par l'API). C'est lui qui sera remplacé.",
      username: "Utilisateur Basic Auth de la DPAPI (compte système ALOHA).",
      password: "Mot de passe — chiffré au repos (AES-256-GCM) dans certfleet, jamais renvoyé en clair.",
      insecure: "Cocher UNIQUEMENT si l'API est en HTTPS avec certificat auto-signé (sinon laisser décoché).",
    },
    verify: "certfleet relit la version après PUT ; ou openssl s_client -connect <VIP>:443 </dev/null 2>/dev/null | openssl x509 -noout -issuer -enddate ; ou la GUI ALOHA (statut doit passer « Valide », plus « Broken chain »).",
    gotcha: "« Broken chain » côté ALOHA = PEM sans les intermédiaires. certfleet envoie TOUJOURS le fullchain → corrige le problème. Ne pas confondre avec le type « HAProxy » (HAProxy Community sur Linux, mode agent). Le cert doit DÉJÀ exister dans le storage (créé une fois via GUI ou POST) : certfleet fait un PUT de remplacement." },
  caddy: { what: "Dépose cert + clé pour un Caddy en mode certificats manuels (tls <cert> <key>), puis recharge Caddy.",
    prepare: AGENT_PREP,
    fields: { agent_id: "Le serveur Caddy.",
      cert_path: "Fichier cert référencé par la directive « tls <cert> <key> ». Ex : /etc/caddy/certs/monsite.crt",
      key_path: "Fichier clé. Ex : /etc/caddy/certs/monsite.key",
      reload_cmd: "caddy reload (recharge le Caddyfile à chaud)" },
    verify: "curl -vI https://monsite",
    gotcha: "Si Caddy gère déjà ses certs en automatique (ACME interne), tu n'as pas besoin de certfleet pour lui. N'utilise ceci que si tu fournis le cert manuellement." },
  traefik: { what: "Dépose cert + clé pour Traefik en provider « file » (le provider fichier recharge tout seul).",
    prepare: AGENT_PREP,
    fields: { agent_id: "Le serveur Traefik.",
      cert_path: "certFile déclaré dans le dynamic config (provider file). Ex : /etc/traefik/certs/monsite.crt",
      key_path: "keyFile. Ex : /etc/traefik/certs/monsite.key" },
    verify: "curl -vI https://monsite",
    gotcha: "Le rechargement automatique n'a lieu que si le provider fichier est lancé avec watch activé (providers.file.watch=true). Sans lui, Traefik garde l'ancien certificat jusqu'à son redémarrage — c'est le piège classique : le fichier est bien à jour sur le disque, mais le certificat servi ne change pas." },
  glpi: { what: "GLPI est une application web (PHP) dont le TLS est assuré par le serveur web devant (Apache ou nginx). On dépose le certificat sur ce serveur web puis on le recharge.",
    prepare: AGENT_PREP,
    fields: { agent_id: "Le serveur qui héberge GLPI.",
      cert_path: "Chemin du certificat référencé dans le vhost GLPI : SSLCertificateFile (Apache) ou ssl_certificate (nginx). Ex : /etc/pki/tls/certs/glpi.crt",
      key_path: "Chemin de la clé : SSLCertificateKeyFile (Apache) ou ssl_certificate_key (nginx). Ex : /etc/pki/tls/private/glpi.key",
      reload_cmd: "Recharge du serveur web : Apache → systemctl reload httpd (ou apachectl graceful) ; nginx → nginx -s reload." },
    verify: "curl -vI https://glpi.exemple  (date d'expiration) ; ou openssl s_client -connect glpi:443 </dev/null 2>/dev/null | openssl x509 -noout -issuer -enddate.",
    gotcha: "Le TLS de GLPI est géré par Apache/nginx, PAS par GLPI. Renseigne les chemins EXACTEMENT comme dans le vhost (grep SSLCertificate /etc/httpd/conf.d/*.conf ou ssl_certificate /etc/nginx/…). Adapte la commande reload au serveur web réellement utilisé." },
  vsftpd: { what: "Dépose cert + clé sur un serveur FTP vsftpd (FTPS) et redémarre le service.",
    prepare: AGENT_PREP,
    fields: { agent_id: "Le serveur vsftpd (ex : ftp-01.example.com).",
      cert_path: "rsa_cert_file de /etc/vsftpd/vsftpd.conf. Ex : /etc/ssl/certs/vsftpd.pem (fullchain)",
      key_path: "rsa_private_key_file. Ex : /etc/ssl/private/vsftpd.key",
      reload_cmd: "vsftpd ne recharge pas à chaud → systemctl restart vsftpd" },
    verify: "openssl s_client -connect serveur:21 -starttls ftp 2>/dev/null | openssl x509 -noout -dates (ou port 990 en FTPS implicite).",
    gotcha: "Contrôle rsa_cert_file / rsa_private_key_file dans vsftpd.conf : les chemins de la cible doivent y correspondre. Un restart coupe brièvement les sessions FTP en cours." },
  servu: { what: "Dépose cert + clé sur un serveur Serv-U.",
    prepare: AGENT_PREP,
    fields: { agent_id: "Le serveur Serv-U.",
      cert_path: "Chemin du certificat (.crt) configuré dans Serv-U (Encryption).",
      key_path: "Chemin de la clé (.key) configurée dans Serv-U." },
    verify: "openssl s_client -connect serveur:443 (ou le port Serv-U).",
    gotcha: "Serv-U relit souvent le cert au redémarrage du service ou via son admin ; le bind 443 peut mettre ~30s à reprendre. Vérifie dans la console Serv-U que le nouveau cert est pris." },
  iis: { what: "Importe le certificat (PFX) dans le magasin Windows et le lie (binding) au site IIS. Agent Windows requis.",
    prepare: ["Installez l'agent Windows sur le serveur : onglet Agents, bascule Windows. Il exige PowerShell 7.", "L'agent Windows construit le PFX localement à partir du cert+clé (la clé privée ne transite jamais en PFX).", "L'agent passe par appcmd.exe et netsh http, jamais par le module WebAdministration : sous PowerShell 7 celui-ci ne renvoie que des objets désérialisés, sans méthodes, et la liaison du certificat échouerait."],
    fields: { agent_id: "Le serveur Windows/IIS.",
      site: "Nom du site IIS. Ex : Default Web Site",
      binding: "Binding HTTPS à mettre à jour. Ex : https :443:",
      store: "Magasin de certificats. Ex : My, c'est-à-dire LocalMachine\\My" },
    verify: "Dans IIS Manager → site → Bindings → https → le nouveau cert. Ou : curl -vI https://site",
    gotcha: "IIS lie par empreinte (thumbprint) : à chaque renouvellement le thumbprint change → il faut REBIND + nettoyer les anciens certs du magasin (sinon il gonfle). L'agent Windows s'en charge." },
  exchange: { what: "Importe le cert (PFX) et l'active pour les services Exchange (IIS, SMTP, IMAP, POP). Agent Windows requis.",
    prepare: ["Agent certfleet WINDOWS sur le serveur Exchange.", "Compte avec droits Exchange (Enable-ExchangeCertificate)."],
    fields: { agent_id: "Le serveur Exchange.",
      services: "Services à activer. Ex : IIS,SMTP,IMAP,POP",
      update_receive_connectors: "Mettre à jour les Receive Connectors (recommandé).",
      purge_old: "Purger les anciens certificats du magasin." },
    verify: "Get-ExchangeCertificate | fl Thumbprint,Services,NotAfter ; test SMTP TLS (openssl s_client -starttls smtp -connect serveur:25).",
    gotcha: "PIÈGE MAJEUR : les Receive Connectors référencent le cert par TlsCertificateName au format <I>issuer<S>subject, JAMAIS par thumbprint. À 47 j le thumbprint change 8×/an → si tu câbles le thumbprint tu casses le SMTP à chaque renouvellement. Enable-ExchangeCertificate -Services … -Force (sinon prompt bloquant)." },
  rds_gateway: { what: "Importe le certificat (au format PFX) dans le magasin Windows LocalMachine\\My puis le lie au rôle Passerelle Bureau à distance (RD Gateway). Agent Windows requis.",
    prepare: ["Installez l'agent Windows sur le serveur RD Gateway : onglet Agents, bascule Windows.",
      "L'agent Windows fabrique le PFX LOCALEMENT (cert + chaîne + clé) — la clé privée ne transite jamais en clair.",
      "Le compte de service de l'agent doit pouvoir importer un cert (LocalMachine\\My) et exécuter Set-RDCertificate (ou écrire la conf RD Gateway)."],
    fields: { agent_id: "Le serveur Windows RD Gateway (par hostname).",
      deployment: "« standalone » = serveur RD Gateway seul (liaison via la conf/registre RD Gateway). « rds-deployment » = déploiement RDS complet (on utilise Set-RDCertificate avec le Connection Broker).",
      connection_broker: "FQDN du Connection Broker (uniquement si deployment = rds-deployment). Ex : broker.exemple.local",
      pfx_password_ref: "Optionnel : référence d'un secret pour protéger le PFX temporaire. Sinon un mot de passe aléatoire est utilisé le temps de l'import." },
    verify: "PowerShell : Get-ChildItem Cert:\\LocalMachine\\My | fl Subject,Thumbprint,NotAfter ; puis teste la connexion RDS via la passerelle (le cert présenté au client doit être le nouveau). Ou : openssl s_client -connect passerelle:443.",
    gotcha: "RD Gateway lie le cert par THUMBPRINT (comme IIS) → à chaque renouvellement le thumbprint change : il faut REBIND + purger les anciens du magasin (l'agent Windows s'en charge). Standalone : la liaison se fait via WMI/registre (HKLM\\SOFTWARE\\Microsoft\\Terminal Server Gateway) ; rds-deployment : via Set-RDCertificate -Role RDGateway. Le nom du cert (SAN) doit correspondre au FQDN public de la passerelle utilisé par les clients RDP." },
  java_keystore: { what: "Importe cert + clé dans un keystore Java (PKCS12) sous un alias, puis redémarre l'appli Java.",
    prepare: AGENT_PREP,
    fields: { agent_id: "Le serveur hébergeant l'appli Java.",
      keystore_path: "Chemin du keystore. Ex : /opt/app/conf/keystore.p12",
      alias: "Alias de l'entrée. Ex : monsite",
      storepass: "Mot de passe du keystore. Sans lui, keytool ne peut ni ouvrir ni réécrire le fichier.",
      restart_cmd: "Commande de redémarrage de l'application, par exemple systemctl restart montomcat. Sans elle, la JVM garde l'ancien certificat en mémoire : le keystore est à jour mais le service continue de servir l'ancien." },
    verify: "keytool -list -keystore keystore.p12 -alias monsite ; puis test TLS sur le port de l'appli.",
    gotcha: "La cible la plus douloureuse : format PKCS12, l'appli doit être redémarrée pour relire le keystore. Attention au mot de passe du keystore (storepass)." },
  uag: { what: "Pousserait le certificat via l'API d'administration de VMware Horizon UAG. Aucun agent à installer. ⚠️ CONNECTEUR NON IMPLÉMENTÉ : le déploiement échouera.",
    prepare: ["Aucun agent à installer (appliance durcie).", "Créer un accès API admin sur l'UAG (port 9443) + stocker les identifiants comme secret dans certfleet."],
    fields: { base_url: "URL admin de l'UAG. Ex : https://uag.exemple:9443", cred_ref: "Référence du secret (login/mdp API admin UAG)." },
    verify: "Ouvre l'URL de l'UAG dans un navigateur → cadenas → nouveau cert.",
    gotcha: "Connecteur non implémenté. L'UAG attend un certificat et sa clé au format PEM via son API REST — contribution bienvenue." },
  f5: { what: "Pousserait le certificat via l'API iControl REST du F5 BIG-IP, pour l'associer au profil Client SSL. ⚠️ CONNECTEUR NON IMPLÉMENTÉ : le déploiement échouera.",
    prepare: ["Compte API sur le F5 (iControl REST) + secret dans certfleet."],
    fields: { base_url: "URL iControl REST. Ex : https://f5-mgmt", profile: "Nom du Client SSL profile à mettre à jour.", cred_ref: "Secret (identifiants API F5)." },
    verify: "openssl s_client -connect vip:443", gotcha: "Connecteur non implémenté — contribution bienvenue." },
  checkpoint: { what: "Pousserait le certificat via l'API de management Check Point. ⚠️ CONNECTEUR NON IMPLÉMENTÉ : le déploiement échouera.",
    prepare: ["Accès API Management Check Point + secret."],
    fields: { base_url: "URL API.", cred_ref: "Secret (identifiants API)." },
    verify: "—", gotcha: "Connecteur non implémenté — contribution bienvenue." },
  api_generic: { what: "Pousse le cert via l'API HTTP d'une appliance FERMÉE, sur laquelle on ne peut PAS installer l'agent certfleet (ex. ECS Dell, Harbor). ⚠️ CONNECTEUR NON IMPLÉMENTÉ : chaque appliance a son API propre, un connecteur dédié reste à écrire. Zabbix, Graylog et NetBox tournent sur Linux avec agent → NE PAS utiliser ce type : passe par une cible Apache/nginx (agent), comme GLPI.",
    prepare: ["Créer un token/compte API sur l'appliance + le stocker comme secret."],
    fields: { base_url: "URL de l'API d'upload du cert.", method: "Méthode HTTP (PUT/POST).", cred_ref: "Secret (token/identifiants)." },
    verify: "Vérifie dans l'admin de l'appliance.", gotcha: "Chaque appliance a son API propre : un connecteur dédié reste à écrire pour chacune. Seul ALOHA est implémenté à ce jour." },
  k8s_secret: { what: "Écrit le certificat dans un Secret kubernetes.io/tls du cluster, via l'API, avec un jeton de ServiceAccount. Sert aux certificats émis À L'EXTÉRIEUR du cluster : sur un cluster où cert-manager gère déjà l'émission, laissez-le faire.",
    prepare: [
      "Créer un ServiceAccount dédié dans le namespace visé, avec le strict nécessaire. Un jeton par cluster : il se révoque seul, sans toucher aux autres.",
      "kubectl -n <ns> create serviceaccount certfleet-deployer",
      "Rôle minimal — écrire LE Secret visé, et redémarrer ce qui le monte. Rien d'autre : ce compte ne doit pas pouvoir lire les autres secrets du namespace.",
      "kubectl -n <ns> create role certfleet-deployer --verb=get,create,update,patch --resource=secrets --resource-name=<nom-du-secret>",
      "kubectl -n <ns> create role certfleet-restart --verb=get,patch --resource=deployments,statefulsets,daemonsets",
      "kubectl -n <ns> create rolebinding certfleet-deployer --role=certfleet-deployer --serviceaccount=<ns>:certfleet-deployer",
      "kubectl -n <ns> create rolebinding certfleet-restart --role=certfleet-restart --serviceaccount=<ns>:certfleet-deployer",
      "Obtenir un jeton de durée limitée : kubectl -n <ns> create token certfleet-deployer --duration=8760h",
      "Récupérer l'autorité du cluster pour ne pas avoir à désactiver la vérification TLS : kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d",
      "Répéter l'opération dans chaque namespace et sur chaque cluster : une cible par couple (cluster, namespace).",
    ],
    fields: { cluster: "Libellé du cluster, pour vous y retrouver dans la liste des cibles.",
      api_url: "URL du serveur d'API. Ex : https://10.0.0.1:6443",
      token: "Jeton du ServiceAccount, chiffré au repos et jamais réaffiché.",
      ca_cert_pem: "Certificat de l'autorité du cluster, en PEM. Le renseigner vaut mieux que désactiver la vérification.",
      insecure: "Dernier recours si vous n'avez pas la CA. Le trafic reste chiffré, mais l'identité du serveur n'est plus vérifiée.",
      namespace: "Namespace où écrire le Secret.",
      secret: "Nom du Secret TLS. S'il existe, il est remplacé ; sinon il est créé.",
      restart: "Ce qu'il faut redémarrer après la pose, séparé par des virgules. Ex : deployment/front,statefulset/api. Sans préfixe, deployment est supposé." },
    verify: "kubectl -n <ns> get secret <nom> -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -dates",
    gotcha: "Un pod qui monte le certificat EN VOLUME garde l'ancien en mémoire jusqu'à son redémarrage : le Secret serait à jour et le service continuerait de servir le certificat périmé. Renseignez le champ « Redémarrages » pour ces cas. Les contrôleurs d'Ingress, eux, relisent le Secret d'eux-mêmes. Ce connecteur ne remplace pas cert-manager : il sert à faire ENTRER dans le cluster un certificat émis ailleurs." },
};

// ── Schéma (idempotent, additif — schéma public infra-global) ──
let _schemaReady = false;
export async function ensureCertSchema() {
  if (_schemaReady) return;
  await query(`CREATE TABLE IF NOT EXISTS cert_certificates(
    id SERIAL PRIMARY KEY,
    common_name TEXT NOT NULL,
    friendly_name TEXT,
    environment TEXT,
    owner TEXT,
    source TEXT DEFAULT 'monitor',
    ca TEXT, serial TEXT, fingerprint_sha256 TEXT,
    not_before TIMESTAMPTZ, not_after TIMESTAMPTZ,
    policy_ca TEXT, policy_challenge TEXT DEFAULT 'dns-01',
    policy_dns_provider TEXT DEFAULT 'gandi',
    renew_before_pct INT DEFAULT 33,
    auto_renew BOOLEAN DEFAULT false,
    notes TEXT, tags TEXT[],
    created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now())`);
  await query(`CREATE TABLE IF NOT EXISTS cert_domains(
    id SERIAL PRIMARY KEY,
    certificate_id INT REFERENCES cert_certificates(id) ON DELETE CASCADE,
    domain TEXT NOT NULL, is_primary BOOLEAN DEFAULT false)`);
  await query(`CREATE TABLE IF NOT EXISTS cert_targets(
    id SERIAL PRIMARY KEY,
    certificate_id INT REFERENCES cert_certificates(id) ON DELETE CASCADE,
    name TEXT, type TEXT NOT NULL, agent_id TEXT,
    params JSONB DEFAULT '{}'::jsonb, deploy_order INT DEFAULT 0,
    post_hook TEXT, verify JSONB DEFAULT '{}'::jsonb,
    enabled BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT now())`);
  await query(`CREATE TABLE IF NOT EXISTS cert_endpoints(
    id SERIAL PRIMARY KEY,
    certificate_id INT REFERENCES cert_certificates(id) ON DELETE SET NULL,
    label TEXT, host TEXT NOT NULL, port INT DEFAULT 443, sni TEXT,
    cluster TEXT, kind TEXT DEFAULT 'https',
    last_checked TIMESTAMPTZ, last_status TEXT, last_not_after TIMESTAMPTZ,
    last_fingerprint TEXT, last_issuer TEXT, last_subject TEXT, last_error TEXT,
    enabled BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT now())`);
  await query(`CREATE TABLE IF NOT EXISTS cert_deployments(
    id SERIAL PRIMARY KEY,
    certificate_id INT REFERENCES cert_certificates(id) ON DELETE CASCADE,
    target_id INT REFERENCES cert_targets(id) ON DELETE SET NULL,
    status TEXT, started_at TIMESTAMPTZ DEFAULT now(), finished_at TIMESTAMPTZ,
    exit_code INT, log TEXT, fingerprint_deployed TEXT, verified BOOLEAN)`);
  // Colonnes d'émission ACME + coffre (clés chiffrées au repos)
  await query(`ALTER TABLE cert_certificates
    ADD COLUMN IF NOT EXISTS leaf_pem TEXT,
    ADD COLUMN IF NOT EXISTS chain_pem TEXT,
    ADD COLUMN IF NOT EXISTS private_key_enc TEXT,
    ADD COLUMN IF NOT EXISTS account_key_enc TEXT,
    ADD COLUMN IF NOT EXISTS acme_directory TEXT,
    ADD COLUMN IF NOT EXISTS issue_status TEXT,
    ADD COLUMN IF NOT EXISTS issue_log TEXT,
    ADD COLUMN IF NOT EXISTS issued_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_issue_error TEXT`);
  await query(`ALTER TABLE cert_deployments ADD COLUMN IF NOT EXISTS adm_command_id BIGINT`);
  // Destinataires d'alerte : chaque cible porte la sienne (« qui prévenir si CE
  // déploiement casse »), avec repli sur le certificat. Les clés *_alert_key
  // évitent de renvoyer le même avertissement à chaque passage du cron.
  await query(`ALTER TABLE cert_targets ADD COLUMN IF NOT EXISTS notify_email TEXT`);
  await query(`ALTER TABLE cert_certificates ADD COLUMN IF NOT EXISTS notify_email TEXT`);
  await query(`ALTER TABLE cert_certificates ADD COLUMN IF NOT EXISTS expiry_alert_key TEXT`);
  await query(`ALTER TABLE cert_endpoints ADD COLUMN IF NOT EXISTS notify_email TEXT`);
  await query(`ALTER TABLE cert_endpoints ADD COLUMN IF NOT EXISTS alert_key TEXT`);
  // Déploiements différés : le master d'une paire HA n'est servi qu'après le
  // backup. On ne peut pas simplement attendre dans le cron (un redémarrage du
  // pod perdrait l'échéance) : elle est donc persistée ici.
  await query(`CREATE TABLE IF NOT EXISTS cert_deploy_queue(
    id SERIAL PRIMARY KEY,
    certificate_id INT REFERENCES cert_certificates(id) ON DELETE CASCADE,
    target_id INT REFERENCES cert_targets(id) ON DELETE CASCADE,
    due_at TIMESTAMPTZ NOT NULL,
    reason TEXT, status TEXT DEFAULT 'pending', error TEXT,
    created_at TIMESTAMPTZ DEFAULT now(), done_at TIMESTAMPTZ)`);
  await query(`CREATE INDEX IF NOT EXISTS cert_deploy_queue_due
    ON cert_deploy_queue(status, due_at)`);
  _schemaReady = true;
}

// Ne jamais renvoyer les secrets par l'API
function _redact(row) {
  if (!row) return row;
  const r = { ...row };
  r.has_private_key = !!r.private_key_enc;
  delete r.private_key_enc; delete r.account_key_enc;
  return r;
}

// Identifiants Gandi (token déchiffré) depuis settings['gandi']
async function getGandiCreds() {
  const r = await query("SELECT value FROM settings WHERE key='gandi'").catch(() => ({ rows: [] }));
  const cfg = r.rows?.[0]?.value;
  if (!cfg || !cfg.token_enc) return null;
  return { token: await vaultDecrypt(cfg.token_enc), scheme: cfg.scheme || "bearer" };
}

const _int = (v) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : null; };
const _str = (v) => (v == null ? null : String(v));

// Petit client HTTP(S) (pour les connecteurs API type ALOHA). Gère le TLS auto-signé
// via insecure. Retourne { status, headers, text }.
function _httpRequest(method, urlStr, { headers = {}, body = null, insecure = false, ca = null, timeout = 20000 } = {}) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(urlStr); } catch { return reject(new Error("URL invalide: " + urlStr)); }
    const isHttps = u.protocol === "https:";
    const lib = isHttps ? https : http;
    const opts = {
      method, hostname: u.hostname, port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search, headers: { ...headers }, timeout,
    };
    if (isHttps && insecure) opts.rejectUnauthorized = false;
    // Autorité interne : la fournir vaut mieux que désactiver la vérification.
    // Un cluster Kubernetes a presque toujours sa propre CA.
    if (isHttps && ca) opts.ca = ca;
    const req = lib.request(opts, (r) => {
      const chunks = [];
      r.on("data", (c) => chunks.push(c));
      r.on("end", () => resolve({ status: r.statusCode, headers: r.headers, text: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("timeout", () => { req.destroy(new Error("timeout")); });
    req.on("error", reject);
    if (body != null) req.write(body);
    req.end();
  });
}

// Champs sensibles, déduits du catalogue plutôt que codés en dur : tout champ
// déclaré « password » dans TARGET_TYPES est un secret. Coder la liste à la
// main revenait à oublier le nouveau champ au premier ajout de type — c'est
// exactement ce qui est arrivé au mot de passe des keystores Java.
const SECRET_FIELDS = new Set(
  TARGET_TYPES.flatMap(t => (t.fields || []).filter(f => f.type === "password").map(f => f.key))
);

// Chiffre les secrets d'une cible avant stockage dans params (jsonb).
// Un champ laissé vide signifie « inchangé » : on conserve alors la valeur
// chiffrée déjà en base, au lieu de l'effacer par mégarde.
async function _encTargetParams(params, previous = null) {
  const p = { ...(params || {}) };
  for (const key of SECRET_FIELDS) {
    const enc = `${key}_enc`;
    if (p[key] != null && p[key] !== "") {
      p[enc] = await vaultEncrypt(String(p[key]));
    } else if (previous && previous[enc]) {
      p[enc] = previous[enc];
    }
    delete p[key];   // ne jamais persister le clair
  }
  return p;
}

// Restitue les secrets en clair, juste avant de les transmettre à l'agent.
async function _decTargetSecrets(params) {
  const out = {};
  for (const key of SECRET_FIELDS) {
    const enc = params?.[`${key}_enc`];
    if (enc) {
      const v = await vaultDecrypt(enc).catch(() => null);
      if (v) out[key] = v;
    }
  }
  return out;
}

// ── Catalogue des types de cible (pour l'UI de settings) ──
// Statut "testé / validé pour l'équipe" par type, stocké dans settings.
async function getTypeStatus() {
  const r = await query("SELECT value FROM settings WHERE key='certfleet_type_status'").catch(() => ({ rows: [] }));
  return r.rows?.[0]?.value || {};
}
router.get("/target-types", async (req, res) => {
  const st = await getTypeStatus().catch(() => ({}));
  res.json(TARGET_TYPES.map(t => ({ ...t, guide: TARGET_GUIDES[t.type] || null, status: st[t.type] || null })));
});
// Marquer/dé-marquer un type comme "testé" (validé pour l'équipe) — admin uniquement
router.post("/target-types/:type/tested", async (req, res) => {
  try {
    // Route déjà protégée par requireAuth au montage : droit d'écriture
    // sur le module certfleet (admin module OU admin global) suffit.
    const type = String(req.params.type || "");
    if (!TARGET_TYPES.some(t => t.type === type)) return res.status(404).json({ error: "Type inconnu" });
    const tested = !!req.body?.tested;
    const note = (req.body?.note != null ? String(req.body.note) : "").slice(0, 500);
    const st = await getTypeStatus().catch(() => ({}));
    if (tested) st[type] = { tested: true, tested_by: req.user?.display_name || req.user?.username || "admin", tested_at: new Date().toISOString(), note };
    else delete st[type];
    await query(
      `INSERT INTO settings(key,value) VALUES('certfleet_type_status',$1::jsonb)
       ON CONFLICT (key) DO UPDATE SET value=$1::jsonb`, [JSON.stringify(st)]
    );
    res.json({ ok: true, type, status: st[type] || null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Agents enrôlés (pour le sélecteur « Agent » d'une cible) ──
router.get("/agents", async (req, res) => {
  try {
    const rows = (await query(
      `SELECT agent_id, hostname, fqdn, ip, os, os_version, last_seen
         FROM agents ORDER BY hostname NULLS LAST, agent_id`
    ).catch(() => ({ rows: [] }))).rows;
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Vue transverse des déploiements : toutes les cibles + cert + dernier déploiement ──
router.get("/deployments/overview", async (req, res) => {
  try {
    // Auto-réconciliation : tout déploiement encore pending/running dont la commande agent est terminée
    await query(`UPDATE cert_deployments d SET status=CASE WHEN ac.exit_code=0 THEN 'success' ELSE 'failed' END,
        exit_code=ac.exit_code, finished_at=COALESCE(d.finished_at,now()), log=COALESCE(NULLIF(d.log,''),ac.result)
      FROM commands ac WHERE d.adm_command_id=ac.id AND d.status IN ('pending','running') AND ac.status IN ('done','failed')`).catch(()=>{});
    const rows = (await query(`
      SELECT t.id AS target_id, t.type, t.name, t.agent_id, t.params, t.enabled, t.deploy_order,
             c.id AS certificate_id, c.common_name, c.friendly_name, c.not_after, c.ca,
             d.status AS last_status, d.started_at AS last_at, d.cmd_result AS last_result, d.cmd_status
      FROM cert_targets t
      JOIN cert_certificates c ON c.id = t.certificate_id
      LEFT JOIN LATERAL (
        SELECT dd.status, dd.started_at, ac.status AS cmd_status, ac.result AS cmd_result
        FROM cert_deployments dd LEFT JOIN commands ac ON ac.id = dd.adm_command_id
        WHERE dd.target_id = t.id ORDER BY dd.started_at DESC LIMIT 1
      ) d ON true
      ORDER BY t.type, c.common_name`)).rows;
    rows.forEach(r => { const s = expiryStatus(r.not_after); r.cert_status = s.status; r.days_left = s.days_left;
      if (r.params?.password_enc) { const p = { ...r.params, has_password: true }; delete p.password_enc; r.params = p; } });
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Vue d'ensemble : KPIs + prochaines échéances (dashboard) ──
router.get("/overview", async (req, res) => {
  try {
    const certs = (await query(`SELECT id, common_name, friendly_name, environment, owner, not_after,
        auto_renew, source FROM cert_certificates`)).rows;
    const eps = (await query(`SELECT id, label, host, port, last_status, last_not_after, last_checked, cluster
        FROM cert_endpoints WHERE enabled=true`)).rows;
    const buckets = { ok: 0, warning: 0, critical: 0, expired: 0, unknown: 0 };
    for (const c of certs) buckets[expiryStatus(c.not_after).status]++;
    // Échéances à venir (certs + endpoints monitorés), triées
    const upcoming = [
      ...certs.map(c => ({ kind: "cert", id: c.id, name: c.friendly_name || c.common_name,
        not_after: c.not_after, ...expiryStatus(c.not_after), auto_renew: c.auto_renew })),
      ...eps.filter(e => e.last_not_after).map(e => ({ kind: "endpoint", id: e.id,
        name: e.label || (e.host + ":" + e.port), not_after: e.last_not_after,
        ...expiryStatus(e.last_not_after), cluster: e.cluster })),
    ].filter(x => x.not_after).sort((a, b) => new Date(a.not_after) - new Date(b.not_after));
    const epStatus = { ok: 0, warning: 0, critical: 0, expired: 0, unreachable: 0, mismatch: 0, unknown: 0 };
    for (const e of eps) epStatus[e.last_status || "unknown"] = (epStatus[e.last_status || "unknown"] || 0) + 1;
    res.json({
      certificates: certs.length, endpoints: eps.length,
      cert_status: buckets, endpoint_status: epStatus,
      upcoming: upcoming.slice(0, 40),
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Inventaire des certificats ──
router.get("/", async (req, res) => {
  try {
    const rows = (await query(`
      SELECT c.*,
        (SELECT json_agg(d.domain ORDER BY d.is_primary DESC, d.domain) FROM cert_domains d WHERE d.certificate_id=c.id) AS domains,
        (SELECT count(*) FROM cert_targets t WHERE t.certificate_id=c.id) AS target_count,
        (SELECT count(*) FROM cert_endpoints e WHERE e.certificate_id=c.id) AS endpoint_count
      FROM cert_certificates c
      ORDER BY c.not_after ASC NULLS LAST, c.common_name`)).rows;
    rows.forEach(r => { const s = expiryStatus(r.not_after); r.status = s.status; r.days_left = s.days_left; r.domains = r.domains || []; });
    res.json(rows.map(_redact));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get("/:id", async (req, res) => {
  try {
    const id = _int(req.params.id);
    const c = (await query("SELECT * FROM cert_certificates WHERE id=$1", [id])).rows[0];
    if (!c) return res.status(404).json({ error: "Certificat introuvable" });
    c.domains = (await query("SELECT * FROM cert_domains WHERE certificate_id=$1 ORDER BY is_primary DESC, domain", [id])).rows;
    c.targets = (await query("SELECT * FROM cert_targets WHERE certificate_id=$1 ORDER BY deploy_order, id", [id])).rows
      .map(t => { if (t.params?.password_enc) { const p = { ...t.params, has_password: true }; delete p.password_enc; t.params = p; } return t; });
    c.endpoints = (await query("SELECT * FROM cert_endpoints WHERE certificate_id=$1 ORDER BY host, port", [id])).rows;
    c.deployments = (await query(`SELECT d.*, ac.status AS cmd_status, ac.result AS cmd_result, ac.exit_code AS cmd_exit,
        t.name AS target_name, t.type AS target_type, t.agent_id AS target_agent
      FROM cert_deployments d
      LEFT JOIN commands ac ON ac.id = d.adm_command_id
      LEFT JOIN cert_targets t ON t.id = d.target_id
      WHERE d.certificate_id=$1 ORDER BY d.started_at DESC LIMIT 50`, [id])).rows;
    // Réconcilie le statut de déploiement depuis la commande agent (done/failed)
    for (const d of c.deployments) {
      if (d.adm_command_id && d.status === "pending" && (d.cmd_status === "done" || d.cmd_status === "failed")) {
        const ns = d.cmd_status === "done" ? "success" : "failed";
        await query("UPDATE cert_deployments SET status=$1, finished_at=now(), exit_code=$2, log=COALESCE($3,log) WHERE id=$4",
          [ns, d.cmd_exit, d.cmd_result, d.id]).catch(() => {});
        d.status = ns;
      }
    }
    Object.assign(c, expiryStatus(c.not_after));
    res.json(_redact(c));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

async function _saveDomains(certId, domains) {
  if (!Array.isArray(domains)) return;
  await query("DELETE FROM cert_domains WHERE certificate_id=$1", [certId]);
  for (let i = 0; i < domains.length; i++) {
    const d = String(domains[i] || "").trim(); if (!d) continue;
    await query("INSERT INTO cert_domains(certificate_id, domain, is_primary) VALUES ($1,$2,$3)", [certId, d, i === 0]);
  }
}

router.post("/", async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.common_name) return res.status(400).json({ error: "common_name requis" });
    const r = await query(`INSERT INTO cert_certificates
      (common_name, friendly_name, environment, owner, source, policy_ca, policy_challenge,
       policy_dns_provider, renew_before_pct, auto_renew, notes, tags)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
      [b.common_name, _str(b.friendly_name), _str(b.environment), _str(b.owner),
       _str(b.source) || "monitor", _str(b.policy_ca), _str(b.policy_challenge) || "dns-01",
       _str(b.policy_dns_provider) || "gandi", _int(b.renew_before_pct) ?? 33,
       !!b.auto_renew, _str(b.notes), Array.isArray(b.tags) ? b.tags : null]);
    const id = r.rows[0].id;
    await _saveDomains(id, b.domains);
    res.status(201).json({ ok: true, id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.put("/:id", async (req, res) => {
  try {
    const id = _int(req.params.id); const b = req.body || {};
    await query(`UPDATE cert_certificates SET
      common_name=COALESCE($2,common_name), friendly_name=$3, environment=$4, owner=$5,
      policy_ca=$6, policy_challenge=$7, policy_dns_provider=$8, renew_before_pct=$9,
      auto_renew=$10, notes=$11, tags=$12, updated_at=now() WHERE id=$1`,
      [id, _str(b.common_name), _str(b.friendly_name), _str(b.environment), _str(b.owner),
       _str(b.policy_ca), _str(b.policy_challenge), _str(b.policy_dns_provider),
       _int(b.renew_before_pct) ?? 33, !!b.auto_renew, _str(b.notes),
       Array.isArray(b.tags) ? b.tags : null]);
    if (b.domains !== undefined) await _saveDomains(id, b.domains);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete("/:id", async (req, res) => {
  try { await query("DELETE FROM cert_certificates WHERE id=$1", [_int(req.params.id)]); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Cibles de déploiement (params par type) ──
router.post("/:id/targets", async (req, res) => {
  try {
    const cid = _int(req.params.id); const b = req.body || {};
    if (!b.type) return res.status(400).json({ error: "type requis" });
    const params = await _encTargetParams(b.params);
    const r = await query(`INSERT INTO cert_targets(certificate_id, name, type, agent_id, params, deploy_order, post_hook, verify, enabled, notify_email)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
      [cid, _str(b.name), _str(b.type), _str(b.agent_id),
       JSON.stringify(params), _int(b.deploy_order) || 0, _str(b.post_hook),
       JSON.stringify(b.verify || {}), b.enabled !== false, _str(b.notify_email)]);
    res.status(201).json({ ok: true, id: r.rows[0].id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
router.put("/targets/:tid", async (req, res) => {
  try {
    const tid = _int(req.params.tid); const b = req.body || {};
    // Les champs secrets laissés vides valent « inchangé » : on relit l'état
    // existant pour ne pas les effacer. Cela vaut pour TOUS les secrets, pas
    // seulement le mot de passe d'API — un keystore Java en a un aussi.
    const previous = (await query("SELECT params FROM cert_targets WHERE id=$1", [tid])).rows[0]?.params || {};
    const params = await _encTargetParams(b.params, previous);
    await query(`UPDATE cert_targets SET name=$2, type=COALESCE($3,type), agent_id=$4,
      params=$5, deploy_order=$6, post_hook=$7, verify=$8, enabled=$9, notify_email=$10 WHERE id=$1`,
      [tid, _str(b.name), _str(b.type), _str(b.agent_id), JSON.stringify(params),
       _int(b.deploy_order) || 0, _str(b.post_hook), JSON.stringify(b.verify || {}), b.enabled !== false,
       _str(b.notify_email)]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Une adresse dont on ignore si elle fonctionne ne protège de rien : on doit
// pouvoir la vérifier tout de suite, sans attendre une vraie panne.
router.post("/alerts/test", async (req, res) => {
  try {
    const dest = _certRecipients(req.body?.email);
    if (!dest.length) return res.status(400).json({ error: "Adresse invalide" });
    const r = await _certAlert({
      to: dest, level: "ok",
      subject: "[certfleet] Test d'alerte certificat",
      intro: "Ceci est un message de test : l'adresse est correctement configurée.",
      rows: [["Destinataire(s)", dest.join(", ")], ["Émis le", new Date().toLocaleString("fr-FR")]],
      hint: "Vous recevrez sur cette adresse les échecs de déploiement, les approches d'échéance et les anomalies TLS."
    });
    if (!r.sent) return res.status(500).json({ error: r.reason === "smtp" ? "SMTP non configuré (voir SMTP_HOST)" : r.reason });
    res.json({ ok: true, to: r.to });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete("/targets/:tid", async (req, res) => {
  try { await query("DELETE FROM cert_targets WHERE id=$1", [_int(req.params.tid)]); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
// Active/désactive l'auto-déploiement d'une cible (case à cocher). enabled=false → exclue du (re)déploiement auto.
router.post("/targets/:tid/enabled", async (req, res) => {
  try {
    const enabled = req.body?.enabled !== false;
    await query("UPDATE cert_targets SET enabled=$2 WHERE id=$1", [_int(req.params.tid), enabled]);
    res.json({ ok: true, enabled });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// Teste la connexion ALOHA + liste les certificats du storage (pour choisir cert_name).
// Accepte soit une cible enregistrée { target_id }, soit des identifiants inline
// { base_url, username, password, insecure } (test avant enregistrement).
router.post("/aloha/list", async (req, res) => {
  try {
    const b = req.body || {};
    let t;
    if (b.target_id) {
      t = (await query("SELECT * FROM cert_targets WHERE id=$1", [_int(b.target_id)])).rows[0];
      if (!t) return res.status(404).json({ error: "Cible introuvable" });
    } else {
      const params = await _encTargetParams({ base_url: b.base_url, username: b.username, password: b.password, insecure: b.insecure });
      t = { params };
    }
    const { base, auth, insecure } = await _alohaCreds(t);
    if (/:4444(\/|$)/.test(base)) return res.status(400).json({ error: "Le port 4444 est la GUI d'admin, PAS la Data Plane API. Utilise le port 5555 (ex. http://192.0.2.30:5555)." });
    const info = await _httpRequest("GET", `${base}/v3/info`, { headers: { Authorization: auth }, insecure });
    if (info.status === 401) {
      // Diagnostic : on trace ce qui a été REÇU (jamais le mot de passe lui-même),
      // seul moyen de distinguer une saisie erronée d'un problème côté appliance.
      const pw = String(b.password ?? "");
      console.warn(`[aloha.list] 401 depuis ${base} | user="${b.username}" | mdp reçu : ${pw.length} caractère(s)`
        + `${pw !== pw.trim() ? " ⚠ ESPACE(S) EN DÉBUT/FIN" : ""}`
        + `${/[^ -~]/.test(pw) ? " ⚠ CARACTÈRE NON IMPRIMABLE" : ""}`
        + ` | insecure=${!!b.insecure}`);
      return res.status(400).json({ error: `Authentification refusée (401) — mot de passe reçu : ${pw.length} caractère(s)`
        + `${pw !== pw.trim() ? ", avec espace(s) en début/fin" : ""}. Vérifie user/mot de passe.` });
    }
    if (info.status !== 200) return res.status(400).json({ error: `DPAPI injoignable : /v3/info HTTP ${info.status}` });
    // Valider que la réponse est bien la Data Plane API (JSON avec api/version), pas la GUI qui répond 200 à tout
    let infoJson = null; try { infoJson = JSON.parse(info.text); } catch {}
    const looksLikeDpapi = infoJson && (infoJson.api || infoJson.version || infoJson.system || infoJson.build_info || infoJson.release_date);
    if (!looksLikeDpapi) return res.status(400).json({ error: "Cette URL répond mais ce n'est PAS la Data Plane API (réponse non-JSON — probablement la GUI 4444). Active la DPAPI sur le port 5555 et pointe dessus." });
    const lr = await _httpRequest("GET", `${base}/v3/services/haproxy/storage/ssl_certificates`, { headers: { Authorization: auth }, insecure });
    let certs = null;
    try { const j = JSON.parse(lr.text); if (Array.isArray(j)) certs = j.map(x => x.storage_name || x.file || x.description || x).filter(Boolean); } catch {}
    if (certs === null) return res.status(400).json({ error: "DPAPI OK mais la liste des certificats n'est pas exploitable (endpoint storage/ssl_certificates inattendu)." });
    res.json({ ok: true, reachable: true, certs });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
// Renomme / met à jour le commentaire d'une cible (champ name)
router.post("/targets/:tid/name", async (req, res) => {
  try {
    const name = String(req.body?.name || "").slice(0, 200);
    await query("UPDATE cert_targets SET name=$2 WHERE id=$1", [_int(req.params.tid), name || null]);
    res.json({ ok: true, name });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Endpoints monitorés (sonde TLS) ──
router.get("/monitor/endpoints", async (req, res) => {
  try {
    const rows = (await query(`SELECT e.*, c.friendly_name AS cert_name, c.fingerprint_sha256 AS expected_fpr
      FROM cert_endpoints e LEFT JOIN cert_certificates c ON c.id=e.certificate_id
      ORDER BY e.cluster NULLS FIRST, e.host, e.port`)).rows;
    rows.forEach(r => { const s = expiryStatus(r.last_not_after); r.days_left = s.days_left; });
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
router.post("/monitor/endpoints", async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.host) return res.status(400).json({ error: "host requis" });
    const kind = _str(b.kind) || "https";
    const port = _int(b.port) || (TLS_KINDS[kind]?.port) || 443;
    const r = await query(`INSERT INTO cert_endpoints(certificate_id, label, host, port, sni, cluster, kind, enabled)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [_int(b.certificate_id), _str(b.label), _str(b.host), port, _str(b.sni), _str(b.cluster), kind, b.enabled !== false]);
    res.status(201).json({ ok: true, id: r.rows[0].id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
router.put("/monitor/endpoints/:eid", async (req, res) => {
  try {
    const eid = _int(req.params.eid); const b = req.body || {};
    await query(`UPDATE cert_endpoints SET certificate_id=$2, label=$3, host=COALESCE($4,host),
      port=$5, sni=$6, cluster=$7, kind=$8, enabled=$9 WHERE id=$1`,
      [eid, _int(b.certificate_id), _str(b.label), _str(b.host), _int(b.port) || 443,
       _str(b.sni), _str(b.cluster), _str(b.kind) || "https", b.enabled !== false]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
router.delete("/monitor/endpoints/:eid", async (req, res) => {
  try { await query("DELETE FROM cert_endpoints WHERE id=$1", [_int(req.params.eid)]); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Applique le résultat d'une sonde à une ligne endpoint + calcule le statut métier.
async function _applyProbe(ep, tries = 6) {
  // Plusieurs sondes pour détecter un endpoint qui sert des certs DIFFÉRENTS
  // selon la requête (replica/copie périmée) → statut « flapping ».
  const results = [];
  for (let i = 0; i < tries; i++) results.push(await probeTls({ host: ep.host, port: ep.port, sni: ep.sni }));
  const oks = results.filter(r => r.ok);
  const norm = f => String(f || "").replace(/:/g, "").toUpperCase();
  const fprs = [...new Set(oks.map(r => norm(r.fingerprint_sha256)).filter(Boolean))];

  let status, error = null, r;
  if (!oks.length) {
    status = "unreachable"; error = results[0]?.error || "injoignable"; r = results[0] || {};
  } else if (fprs.length > 1) {
    // FLAPPING : au moins 2 certificats distincts servis sur les sondes
    status = "flapping";
    const byFpr = new Map();
    for (const o of oks) { const k = norm(o.fingerprint_sha256); if (!byFpr.has(k)) byFpr.set(k, { o, n: 0 }); byFpr.get(k).n++; }
    const variants = [...byFpr.values()].map(v => `${v.n}/${oks.length} ${v.o.issuer_cn || v.o.issuer_o || "?"} exp ${String(v.o.not_after).slice(0, 10)} (${expiryStatus(v.o.not_after).status})`);
    error = "⚠️ Certificats incohérents servis (flapping) : " + variants.join(" | ");
    // On affiche le PIRE (échéance la plus proche) pour attirer l'attention
    r = oks.slice().sort((a, b) => new Date(a.not_after) - new Date(b.not_after))[0];
  } else {
    r = oks[0];
    const es = expiryStatus(r.not_after).status;
    status = es === "ok" ? "ok" : es;
    if (ep.expected_fpr && r.fingerprint_sha256 && norm(ep.expected_fpr) !== norm(r.fingerprint_sha256)) status = "mismatch";
  }
  await query(`UPDATE cert_endpoints SET last_checked=now(), last_status=$2, last_not_after=$3,
    last_fingerprint=$4, last_issuer=$5, last_subject=$6, last_error=$7 WHERE id=$1`,
    [ep.id, status, r.not_after || null, r.fingerprint_sha256 || null,
     r.issuer_cn || r.issuer_o || null, r.subject_cn || null, error]);
  return { ...(oks[0] || results[0] || {}), status, flapping: fprs.length > 1, variants: fprs.length };
}

// Sonde un endpoint monitoré maintenant
router.post("/monitor/endpoints/:eid/check", async (req, res) => {
  try {
    const eid = _int(req.params.eid);
    const ep = (await query(`SELECT e.*, c.fingerprint_sha256 AS expected_fpr FROM cert_endpoints e
      LEFT JOIN cert_certificates c ON c.id=e.certificate_id WHERE e.id=$1`, [eid])).rows[0];
    if (!ep) return res.status(404).json({ error: "Endpoint introuvable" });
    res.json(await _applyProbe(ep));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Sonde TOUS les endpoints actifs
router.post("/monitor/check-all", async (req, res) => {
  try {
    const eps = (await query(`SELECT e.*, c.fingerprint_sha256 AS expected_fpr FROM cert_endpoints e
      LEFT JOIN cert_certificates c ON c.id=e.certificate_id WHERE e.enabled=true`)).rows;
    let ok = 0, ko = 0;
    // Concurrence limitée pour ne pas saturer
    const CONC = 8;
    for (let i = 0; i < eps.length; i += CONC) {
      const batch = eps.slice(i, i + CONC);
      const rs = await Promise.all(batch.map(ep => _applyProbe(ep).catch(() => null)));
      rs.forEach(r => { if (r && r.ok) ok++; else ko++; });
    }
    res.json({ checked: eps.length, ok, ko });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Sonde ad-hoc (bouton « Tester » de l'UI) — ne persiste rien
router.get("/probe", async (req, res) => {
  try {
    const host = _str(req.query.host); if (!host) return res.status(400).json({ error: "host requis" });
    const kind = _str(req.query.kind) || "https";
    const port = _int(req.query.port) || (TLS_KINDS[kind]?.port) || 443;
    res.json(await probeTls({ host, port, sni: _str(req.query.sni) }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Émission / renouvellement ACME (async) ──
const _issuing = new Set();
const _relName = (recordName, zone) => recordName.endsWith("." + zone) ? recordName.slice(0, -(zone.length + 1)) : recordName;

// Émission complète (réutilisée par la route manuelle ET le cron d'auto-renouvellement)
async function _issueCert(id, env, actor) {
  const dir = env === "production" ? ACME_DIRECTORIES.letsencrypt : ACME_DIRECTORIES["letsencrypt-staging"];
  const cert = (await query("SELECT * FROM cert_certificates WHERE id=$1", [id])).rows[0];
  if (!cert) return { ok: false, error: "Certificat introuvable" };
  const doms = (await query("SELECT domain FROM cert_domains WHERE certificate_id=$1 ORDER BY is_primary DESC, domain", [id])).rows.map(r => r.domain);
  const identifiers = doms.length ? doms : [cert.common_name];
  const creds = await getGandiCreds();
  if (!creds) { await query("UPDATE cert_certificates SET issue_status='error', last_issue_error=$2 WHERE id=$1", [id, "Token Gandi non configuré"]).catch(() => {}); return { ok: false, error: "Token Gandi non configuré" }; }
  await query("UPDATE cert_certificates SET issue_status='running', last_issue_error=NULL, issue_log='', acme_directory=$2 WHERE id=$1", [id, dir]);
  const logs = []; const log = (m) => logs.push(new Date().toISOString().slice(11, 19) + " " + m);
  const { token, scheme } = creds;
  const setDns = async ({ recordName, values, value }) => { const vals = values || [value]; const target = await resolveChallengeTarget(recordName); if (target !== recordName) log(`délégation CNAME : ${recordName} → ${target}`); const zone = await gandiFindZone({ token, scheme, fqdn: target }); await gandiUpsertTxt({ token, scheme, zone, name: _relName(target, zone), values: vals }); };
  const removeDns = async ({ recordName }) => { const target = await resolveChallengeTarget(recordName); const zone = await gandiFindZone({ token, scheme, fqdn: target }); await gandiDeleteTxt({ token, scheme, zone, name: _relName(target, zone) }); };
  const contact = process.env.ACME_CONTACT_EMAIL || (cert.owner && /@/.test(cert.owner) ? cert.owner : "it@example.net");
  try {
    log(`émission ${env} pour ${identifiers.join(", ")} (${actor})`);
    const r0 = await issueCertificate({ directoryUrl: dir, accountKeyPem: cert.account_key_enc ? await vaultDecrypt(cert.account_key_enc) : null, identifiers, email: contact, setDns, removeDns, waitDns: true, log });
    const issuerCn = String(r0.issuer || "").split("\n").map(s => s.trim()).find(s => s.startsWith("CN="))?.slice(3) || String(r0.issuer || "").replace(/\n/g, " ").trim();
    await query(`UPDATE cert_certificates SET issue_status='success', issued_at=NOW(),
      leaf_pem=$2, chain_pem=$3, private_key_enc=$4, account_key_enc=$5,
      not_before=$6, not_after=$7, ca=$8, serial=$9, fingerprint_sha256=$10,
      source='acme', issue_log=$11, last_issue_error=NULL, updated_at=NOW() WHERE id=$1`,
      [id, r0.leafPem, r0.chainPem, await vaultEncrypt(r0.privateKeyPem), await vaultEncrypt(r0.accountKeyPem),
       r0.notBefore, r0.notAfter, issuerCn, r0.serial, r0.fingerprint, logs.join("\n")]);
    await query("INSERT INTO cert_deployments(certificate_id,target_id,status,finished_at,log,fingerprint_deployed,verified) VALUES($1,NULL,'success',NOW(),$2,$3,false)",
      [id, `Émission ACME (${env}) par ${actor} : ${identifiers.join(", ")}`, r0.fingerprint]);
    return { ok: true, fingerprint: r0.fingerprint, notAfter: r0.notAfter };
  } catch (e) {
    log("ÉCHEC : " + e.message);
    await query("UPDATE cert_certificates SET issue_status='error', last_issue_error=$2, issue_log=$3 WHERE id=$1", [id, e.message, logs.join("\n")]).catch(() => {});
    return { ok: false, error: e.message };
  }
}

router.post("/:id/issue", async (req, res) => {
  const id = _int(req.params.id);
  const env = (req.body?.environment === "production") ? "production" : "staging";
  try {
    const cert = (await query("SELECT id FROM cert_certificates WHERE id=$1", [id])).rows[0];
    if (!cert) return res.status(404).json({ error: "Certificat introuvable" });
    if (!(await getGandiCreds())) return res.status(400).json({ error: "Token Gandi non configuré (Admin › Intégrations)" });
    if (_issuing.has(id)) return res.status(409).json({ error: "Émission déjà en cours pour ce certificat" });
    _issuing.add(id);
    res.status(202).json({ started: true, environment: env });
    const actor = req.user?.display_name || req.user?.username || "manuel";
    _issueCert(id, env, actor).finally(() => _issuing.delete(id));
  } catch (e) { _issuing.delete(id); if (!res.headersSent) res.status(500).json({ error: e.message }); }
});

// Toggle du renouvellement automatique (bouton « auto »)
router.post("/:id/auto-renew", async (req, res) => {
  try {
    const enabled = req.body?.enabled !== false;
    await query("UPDATE cert_certificates SET auto_renew=$2, updated_at=NOW() WHERE id=$1", [_int(req.params.id), enabled]);
    res.json({ ok: true, auto_renew: enabled });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Déploiement sur une cible via l'agent (kind=cert, clé chiffrée hybride) ──
// ── Connecteur API HAProxy ALOHA (Data Plane API) ──
// Remplace à chaud le PEM combiné (fullchain + clé) du certificat existant dans le
// storage de l'ALOHA. Doc : PUT /v3/services/haproxy/storage/ssl_certificates/{nom}?version=N
async function _alohaCreds(t) {
  const p = t.params || {};
  const base = String(p.base_url || "").replace(/\/+$/, "");
  if (!base) throw new Error("URL Data Plane API manquante (base_url)");
  const username = p.username || "";
  if (!username) throw new Error("Utilisateur API manquant (username)");
  let password = "";
  if (p.password_enc) { try { password = await vaultDecrypt(p.password_enc); } catch { throw new Error("Mot de passe API illisible (coffre) — ré-enregistre la cible"); } }
  if (!password) throw new Error("Mot de passe API manquant — édite la cible pour le (re)saisir");
  const auth = "Basic " + Buffer.from(`${username}:${password}`).toString("base64");
  return { base, auth, insecure: !!p.insecure };
}
async function _alohaGetVersion({ base, auth, insecure }) {
  const r = await _httpRequest("GET", `${base}/v3/services/haproxy/configuration/version`, { headers: { Authorization: auth }, insecure });
  if (r.status !== 200) throw new Error(`DPAPI version HTTP ${r.status} — auth/URL ? (${r.text.slice(0, 120)})`);
  const v = parseInt(String(r.text).replace(/[^0-9]/g, ""), 10);
  if (!Number.isFinite(v)) throw new Error("Version de conf DPAPI illisible");
  return v;
}
async function _deployAloha(cert, t, actor) {
  const { base, auth, insecure } = await _alohaCreds(t);
  const certName = String((t.params || {}).cert_name || "").trim();
  if (!certName) throw new Error("Nom du fichier certificat ALOHA manquant (cert_name) — utilise « Lister » pour le trouver");
  const fullchain = [cert.leaf_pem, cert.chain_pem].filter(Boolean).join("\n").trim() + "\n";
  const keyPem = (await vaultDecrypt(cert.private_key_enc)).trim() + "\n";
  const pem = fullchain + keyPem; // PEM combiné attendu par ALOHA
  // Pré-vol : valide l'URL + les identifiants et donne une erreur claire avant
  // d'envoyer le PEM. La version de conf ne sert PAS au PUT ci-dessous.
  await _alohaGetVersion({ base, auth, insecure });
  // PUT = remplacement du certificat existant (hot-update).
  // Paramètres réels de l'endpoint (spec DPAPI v3 de l'appliance) : name (path),
  // data (body, text/plain), skip_reload et force_reload (query). Il n'y a PAS
  // de paramètre `version` — celui-ci n'appartient qu'aux endpoints /configuration.
  // skip_reload=false par défaut → un reload est demandé, donc le certificat est
  // réellement servi ; force_reload évite d'attendre le reload-delay de l'appliance.
  const url = `${base}/v3/services/haproxy/storage/ssl_certificates/${encodeURIComponent(certName)}?force_reload=true`;
  let r = await _httpRequest("PUT", url, { headers: { Authorization: auth, "Content-Type": "text/plain" }, body: pem, insecure });
  const ok = r.status >= 200 && r.status < 300;
  const reloadId = r.headers?.["reload-id"] || r.headers?.["Reload-ID"] || null;
  const log = `ALOHA DPAPI PUT ${certName} → HTTP ${r.status}`
    + (ok ? ` (remplacé, reload demandé${reloadId ? " — Reload-ID " + reloadId : ""})` : " " + r.text.slice(0, 300));
  const dep = (await query(
    "INSERT INTO cert_deployments (certificate_id, target_id, status, exit_code, log, finished_at) VALUES ($1,$2,$3,$4,$5,now()) RETURNING id",
    [cert.id, t.id, ok ? "success" : "failed", ok ? 0 : 1, log]
  )).rows[0];
  if (!ok) throw new Error(log);
  return { deployment_id: dep.id, target: `ALOHA ${base}`, cert_name: certName, hot_update: true, http_status: r.status, reload_id: reloadId };
}

// ── Connecteur Kubernetes ────────────────────────────────────────────────────
//
// Écrit un Secret de type kubernetes.io/tls par appel direct à l'API du
// cluster, avec un jeton de ServiceAccount. Un jeton par cluster : il se
// révoque seul, sans toucher aux autres.
//
// Le redémarrage n'est pas un supplément d'âme. Un pod qui monte le certificat
// en volume garde l'ancien en mémoire tant qu'il n'a pas redémarré : le Secret
// serait à jour et le service continuerait de servir le certificat périmé.
// Les contrôleurs d'Ingress, eux, relisent le Secret d'eux-mêmes.
async function _deployK8s(cert, t, actor) {
  const p = t.params || {};
  const base = String(p.api_url || "").replace(/\/+$/, "");
  const ns = String(p.namespace || "").trim();
  const nom = String(p.secret || "").trim();
  if (!base || !ns || !nom) throw new Error("URL de l'API, namespace et nom du Secret sont requis");

  const secrets = await _decTargetSecrets(p);
  const token = secrets.token || "";
  if (!token) throw new Error("Jeton du ServiceAccount manquant sur la cible");

  const fullchain = [cert.leaf_pem, cert.chain_pem].filter(Boolean).join("\n").trim() + "\n";
  const keyPem = (await vaultDecrypt(cert.private_key_enc)).trim() + "\n";

  const opts = {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
    insecure: !!p.insecure,
    ca: p.ca_cert_pem ? String(p.ca_cert_pem) : null,
  };
  const corps = JSON.stringify({
    apiVersion: "v1", kind: "Secret", type: "kubernetes.io/tls",
    metadata: { name: nom, namespace: ns },
    data: {
      "tls.crt": Buffer.from(fullchain, "utf8").toString("base64"),
      "tls.key": Buffer.from(keyPem, "utf8").toString("base64"),
    },
  });
  const chemin = `${base}/api/v1/namespaces/${encodeURIComponent(ns)}/secrets`;
  const journal = [];

  // On remplace d'abord ; si le Secret n'existe pas encore, on le crée.
  let r = await _httpRequest("PUT", `${chemin}/${encodeURIComponent(nom)}`,
    { ...opts, headers: { ...opts.headers, "Content-Type": "application/json" }, body: corps });
  if (r.status === 404) {
    journal.push(`Secret ${ns}/${nom} absent — création`);
    r = await _httpRequest("POST", chemin,
      { ...opts, headers: { ...opts.headers, "Content-Type": "application/json" }, body: corps });
  }
  let ok = r.status >= 200 && r.status < 300;
  journal.push(`Secret ${ns}/${nom} → HTTP ${r.status}` + (ok ? " (posé)" : " " + r.text.slice(0, 300)));

  // Redémarrages demandés : même annotation que « kubectl rollout restart ».
  if (ok && String(p.restart || "").trim()) {
    for (const brut of String(p.restart).split(",").map(x => x.trim()).filter(Boolean)) {
      const [genre, cible] = brut.includes("/") ? brut.split("/") : ["deployment", brut];
      const pluriel = { deployment: "deployments", statefulset: "statefulsets", daemonset: "daemonsets" }[genre.toLowerCase()];
      if (!pluriel) { journal.push(`« ${brut} » ignoré : type inconnu`); continue; }
      const patch = JSON.stringify({ spec: { template: { metadata: { annotations: {
        "kubectl.kubernetes.io/restartedAt": new Date().toISOString(),
      } } } } });
      const rr = await _httpRequest("PATCH",
        `${base}/apis/apps/v1/namespaces/${encodeURIComponent(ns)}/${pluriel}/${encodeURIComponent(cible)}`,
        { ...opts, headers: { ...opts.headers, "Content-Type": "application/strategic-merge-patch+json" }, body: patch });
      const rok = rr.status >= 200 && rr.status < 300;
      journal.push(`redémarrage ${genre}/${cible} → HTTP ${rr.status}` + (rok ? "" : " " + rr.text.slice(0, 200)));
      if (!rok) ok = false;
    }
  } else if (ok) {
    journal.push("aucun redémarrage demandé — les pods qui montent le certificat en volume garderont l'ancien jusqu'à leur prochain démarrage");
  }

  const log = journal.join(" | ");
  const dep = (await query(
    "INSERT INTO cert_deployments (certificate_id, target_id, status, exit_code, log, finished_at) VALUES ($1,$2,$3,$4,$5,now()) RETURNING id",
    [cert.id, t.id, ok ? "success" : "failed", ok ? 0 : 1, log]
  )).rows[0];
  if (!ok) throw new Error(log);
  return { deployment_id: dep.id, target: `${p.cluster || base} ${ns}/${nom}`, log };
}

async function _deployToTarget(cert, t, actor) {
  if (!cert.leaf_pem || !cert.private_key_enc) throw new Error("Certificat non émis — émets-le d'abord");
  const typeDef = TARGET_TYPES.find(x => x.type === t.type);
  if (typeDef && typeDef.mode === "api" && t.type === "aloha") return _deployAloha(cert, t, actor);
  if (typeDef && typeDef.mode === "api" && t.type === "k8s_secret") return _deployK8s(cert, t, actor);
  if (!typeDef || typeDef.mode !== "agent") {
    throw new Error(typeDef?.mode === "api"
      ? `Le connecteur API « ${t.type} » n'est pas implémenté. Seul ALOHA l'est à ce jour.`
      : `Le type « ${t.type} » est en surveillance seule : rien n'est déployé depuis certfleet.`);
  }
  if (!t.agent_id) throw new Error("Cible sans agent (choisis un agent enrôlé)");
  const ag = (await query("SELECT pubkey FROM agents WHERE agent_id=$1", [t.agent_id])).rows[0];
  if (!ag?.pubkey) throw new Error("Agent sans clé publique (réenrôle l'agent)");
  const params = t.params || {};
  const cert_path = params.cert_path || params.pem_path || "";
  const key_path = params.key_path || params.pem_path || "";

  // Deux familles de cibles, qui n'attendent pas la même chose :
  //   — « fichier » : le certificat est écrit sur le disque, aux chemins donnés ;
  //   — « magasin » : Windows et Java le rangent dans un magasin, un chemin
  //     n'aurait alors aucun sens.
  // Exiger cert_path pour toutes rendait IIS, Exchange, la passerelle RDS et
  // les keystores Java inutilisables : ils échouaient avant même de partir.
  const STORE_TYPES = new Set(["iis", "exchange", "rds_gateway", "java_keystore"]);
  const storeMode = STORE_TYPES.has(t.type);
  if (!storeMode && (!cert_path || !key_path)) {
    throw new Error("Paramètres cert_path/key_path manquants sur la cible");
  }

  const fullchain = [cert.leaf_pem, cert.chain_pem].filter(Boolean).join("\n") + "\n";
  const keyPem = await vaultDecrypt(cert.private_key_enc);
  // Chiffrement hybride : AES-256-CBC(clé privée) + RSA-OAEP(clé AES, pubkey agent)
  const aesKey = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const cph = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  const keyCipher = Buffer.concat([cph.update(keyPem, "utf8"), cph.final()]);
  const aesKeyEnc = crypto.publicEncrypt({ key: ag.pubkey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, aesKey);
  // Chaine intermediaire SEPAREE (optionnelle) : certains serveurs ne lisent que le
  // PREMIER certificat du fichier .crt et attendent la CA dans un reglage a part
  // (Serv-U notamment). On ecrit alors chain_pem dans chain_path.
  const chain_path = params.chain_path || "";
  // Les paramètres propres au type (site IIS, alias du keystore, services
  // Exchange…) sont transmis tels quels : c'est l'agent qui sait quoi en faire.
  // On retire ceux déjà portés explicitement, pour ne pas les envoyer en double.
  const extra = { ...params };
  for (const k of ["cert_path", "key_path", "pem_path", "chain_path", "reload_cmd", "agent_id"]) {
    delete extra[k];
  }
  // Les valeurs chiffrées au repos ne servent à rien à l'agent : on les retire
  // et on transmet les secrets par un canal chiffré à part (voir plus bas).
  for (const k of Object.keys(extra)) if (k.endsWith("_enc")) delete extra[k];

  // Les paramètres secrets — mot de passe d'un keystore, par exemple — ne
  // doivent pas atterrir en clair dans commands.payload, qui reste lisible en
  // base. On les chiffre avec la MÊME clé AES que la clé privée : seul cet
  // agent peut les lire, puisque lui seul détient la clé RSA qui la déchiffre.
  const secrets = await _decTargetSecrets(params);
  let secretsBlob = null;
  if (Object.keys(secrets).length) {
    const siv = crypto.randomBytes(16);
    const sc = crypto.createCipheriv("aes-256-cbc", aesKey, siv);
    secretsBlob = {
      secrets_iv: siv.toString("hex"),
      secrets_cipher: Buffer.concat([sc.update(JSON.stringify(secrets), "utf8"), sc.final()]).toString("base64"),
    };
  }

  const payload = {
    target_type: t.type,
    mode: storeMode ? "store" : "file",
    cert_pem: fullchain, cert_path, key_path,
    ...(chain_path ? { chain_path, chain_pem: (cert.chain_pem || "").trim() + "\n" } : {}),
    key_iv: iv.toString("hex"),
    aeskey_enc: aesKeyEnc.toString("base64"),
    key_cipher: keyCipher.toString("base64"),
    reload_cmd: params.reload_cmd || "",
    common_name: cert.common_name || "",
    params: extra,
    ...(secretsBlob || {}),
  };
  const cmd = (await query(
    "INSERT INTO commands (agent_id, action, kind, payload, status, proposed_by, approved_by) VALUES ($1,'deploy','cert',$2,'approved',$3,$3) RETURNING id",
    [t.agent_id, JSON.stringify(payload), actor]
  )).rows[0];
  const dep = (await query(
    "INSERT INTO cert_deployments (certificate_id, target_id, status, adm_command_id, log) VALUES ($1,$2,'pending',$3,$4) RETURNING id",
    [cert.id, t.id, cmd.id, `Commande ${t.type} → ${t.agent_id} : ${storeMode ? "magasin de certificats" : cert_path}`]
  )).rows[0];
  return { command_id: cmd.id, deployment_id: dep.id, agent_id: t.agent_id,
           cert_path: storeMode ? null : cert_path, mode: storeMode ? "store" : "file" };
}

router.post("/targets/:tid/deploy", async (req, res) => {
  try {
    const t = (await query("SELECT * FROM cert_targets WHERE id=$1", [_int(req.params.tid)])).rows[0];
    if (!t) return res.status(404).json({ error: "Cible introuvable" });
    const cert = (await query("SELECT * FROM cert_certificates WHERE id=$1", [t.certificate_id])).rows[0];
    const actor = req.user?.display_name || req.user?.username || "certfleet";
    res.json({ ok: true, ...(await _deployToTarget(cert, t, actor)) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

router.post("/:id/deploy", async (req, res) => {
  try {
    const cert = (await query("SELECT * FROM cert_certificates WHERE id=$1", [_int(req.params.id)])).rows[0];
    if (!cert) return res.status(404).json({ error: "Certificat introuvable" });
    const tgts = (await query("SELECT * FROM cert_targets WHERE certificate_id=$1 AND enabled=true ORDER BY deploy_order, id", [cert.id])).rows;
    if (!tgts.length) return res.status(400).json({ error: "Aucune cible active" });
    const actor = req.user?.display_name || req.user?.username || "certfleet";
    const { results, differes } = await _deployStaged(cert, tgts, actor);
    res.json({ ok: true, results, differes });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Téléchargement (fallback manuel si l'agent est indisponible) ──
// Parties publiques (fullchain/chain/leaf) : tout utilisateur. Clé/bundle : admin + tracé.
router.get("/:id/download", async (req, res) => {
  try {
    const id = _int(req.params.id);
    const what = String(req.query.what || "fullchain");
    const c = (await query("SELECT * FROM cert_certificates WHERE id=$1", [id])).rows[0];
    if (!c) return res.status(404).json({ error: "Certificat introuvable" });
    if (!c.leaf_pem) return res.status(400).json({ error: "Certificat non émis (rien à télécharger)" });
    const fullchain = [c.leaf_pem, c.chain_pem].filter(Boolean).join("\n").replace(/\n+$/, "") + "\n";
    const base = String(c.common_name || "certificat").replace(/^\*/, "wildcard").replace(/[^a-zA-Z0-9._-]/g, "_");
    const send = (name, body) => {
      res.setHeader("Content-Type", "application/x-pem-file");
      res.setHeader("Content-Disposition", `attachment; filename="${name}"`);
      res.send(body);
    };
    if (what === "leaf")      return send(base + ".crt", c.leaf_pem.replace(/\n+$/, "") + "\n");
    if (what === "chain")     return send(base + ".chain.pem", (c.chain_pem || "").replace(/\n+$/, "") + "\n");
    if (what === "fullchain") return send(base + ".fullchain.pem", fullchain);
    if (what === "key" || what === "bundle") {
      if (!req.user?.is_admin) return res.status(403).json({ error: "Réservé aux administrateurs (contient la clé privée)" });
      if (!c.private_key_enc) return res.status(400).json({ error: "Aucune clé privée stockée (certificat non émis par certfleet)" });
      console.log(`[certfleet] AUDIT téléchargement ${what} du cert #${id} (${c.common_name}) par ${req.user?.username || req.user?.id}`);
      const key = await vaultDecrypt(c.private_key_enc);
      if (what === "key") return send(base + ".key", key.replace(/\n+$/, "") + "\n");
      return send(base + ".bundle.pem", fullchain + key.replace(/\n+$/, "") + "\n"); // fullchain + clé
    }
    return res.status(400).json({ error: "paramètre 'what' invalide (fullchain|chain|leaf|key|bundle)" });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Cron de supervision : sonde périodique de tous les endpoints ──
// setInterval retombe silencieusement a 1 ms au-dela de 2^31-1 : un intervalle
// de plus de ~24 jours ferait tourner le cron en boucle au lieu de l'espacer.
// On plafonne, en le disant, plutot que de laisser la surprise arriver en prod.
function safeIntervalMs(minutes, label) {
  const MAX = 2147483647;
  const ms = Math.max(1, Number(minutes) || 0) * 60000;
  if (ms > MAX) {
    console.warn(`[${label}] intervalle de ${minutes} min trop grand pour setInterval, ramené à 24 jours`);
    return MAX;
  }
  return ms;
}

// ═════════════════════════════════════════════
// ALERTES — un renouvellement qui échoue à 3 h du matin ne sert à rien s'il ne
// réveille personne. Tout était déjà détecté (journal du cron, table des
// déploiements, sonde TLS) mais uniquement pour qui regardait l'écran.
// ═════════════════════════════════════════════

// La configuration vient d'abord de l'environnement — c'est ce qui se prête le
// mieux à un déploiement conteneurisé — puis, à défaut, de la table settings.
async function _certTransporter() {
  let smtp = {};
  if (process.env.SMTP_HOST) {
    smtp = {
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || "25", 10),
      secure: process.env.SMTP_SECURE === "true",
      user: process.env.SMTP_USER, pass: process.env.SMTP_PASS,
      from: process.env.SMTP_FROM
    };
  } else {
    const r = await query("SELECT value FROM settings WHERE key='smtp'").catch(() => ({ rows: [] }));
    smtp = r.rows?.[0]?.value || {};
  }
  if (!smtp.host || smtp.enabled === false) return null;
  const nodemailer = (await import("nodemailer")).default;
  const opts = { host: smtp.host, port: smtp.port || 25, secure: !!smtp.secure, tls: { rejectUnauthorized: false } };
  if (smtp.user && (smtp.pass || smtp.password)) opts.auth = { user: smtp.user, pass: smtp.pass || smtp.password };
  return { transporter: nodemailer.createTransport(opts), from: smtp.from || smtp.user || "certfleet@localhost" };
}
const _cEsc = s => String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// Accepte « a@b.fr, c@d.fr » ou des adresses séparées par des points-virgules.
// Une adresse invalide est écartée sans faire échouer l'envoi aux autres.
export function _certRecipients(sources) {
  const out = new Set();
  for (const s of [].concat(sources)) {
    for (const part of String(s || "").split(/[,;\s]+/)) {
      const a = part.trim();
      if (a && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(a)) out.add(a);
    }
  }
  return [...out];
}

async function _certAlert({ to, subject, level = "error", intro, rows = [], hint }) {
  const dest = _certRecipients(to);
  if (!dest.length) return { sent: false, reason: "aucun destinataire" };
  const mailer = await _certTransporter().catch(() => null);
  if (!mailer) { console.warn("[certAlert] SMTP non configuré, alerte perdue :", subject); return { sent: false, reason: "smtp" }; }
  const coul = level === "ok" ? "#15803d" : level === "warn" ? "#b45309" : "#b91c1c";
  const html = `<div style="font-family:Segoe UI,Arial,sans-serif;color:#1d3557;">`
    + `<p style="color:${coul};font-weight:700;font-size:15px;margin:0 0 10px;">${_cEsc(intro)}</p>`
    + (rows.length ? `<table style="border-collapse:collapse;font-size:13px;margin:10px 0;">`
        + rows.map(([k, v]) => `<tr><td style="padding:5px 14px 5px 0;color:#64748b;white-space:nowrap;">${_cEsc(k)}</td>`
            + `<td style="padding:5px 0;"><b>${_cEsc(v)}</b></td></tr>`).join("") + `</table>` : "")
    + (hint ? `<p style="background:#f8fafc;border-left:3px solid ${coul};padding:8px 12px;font-size:13px;">${_cEsc(hint)}</p>` : "")
    + `<p style="color:#94a3b8;font-size:12px;">— certfleet</p></div>`;
  try {
    await mailer.transporter.sendMail({ from: mailer.from, to: dest.join(","), subject, html });
    console.log(`[certAlert] ${subject} → ${dest.join(", ")}`);
    return { sent: true, to: dest };
  } catch (e) { console.warn("[certAlert] envoi impossible :", e.message); return { sent: false, reason: e.message }; }
}

// Destinataires d'un certificat : son adresse propre + celles de ses cibles actives.
async function _certAllRecipients(certId, certMail) {
  const rs = (await query("SELECT notify_email FROM cert_targets WHERE certificate_id=$1 AND enabled=true", [certId])).rows;
  return [certMail, ...rs.map(x => x.notify_email)];
}

// Filet de sécurité INDÉPENDANT du renouvellement : si un certificat approche de
// sa fin quelle qu'en soit la raison — auto-renouvellement désactivé, cron
// arrêté, échecs répétés — quelqu'un doit l'apprendre avant les utilisateurs.
//
// Ordre CROISSANT obligatoire : .find() retient le premier seuil satisfait,
// donc le plus petit palier encore valable. Classé en décroissant, tout
// tomberait dans « 30 j » et plus aucune relance ne partirait ensuite.
export const _SEUILS_ALERTE = [1, 3, 7, 14, 30];
async function _certExpiryWatch() {
  const certs = (await query(`SELECT id, common_name, not_after, notify_email, expiry_alert_key, auto_renew
    FROM cert_certificates WHERE not_after IS NOT NULL AND not_after > now() - interval '30 days'`)).rows;
  for (const c of certs) {
    const jours = Math.floor((new Date(c.not_after).getTime() - Date.now()) / 86400000);
    const seuil = jours < 0 ? "expire" : _SEUILS_ALERTE.find(s => jours <= s);
    if (seuil === undefined) {
      if (c.expiry_alert_key) await query("UPDATE cert_certificates SET expiry_alert_key=NULL WHERE id=$1", [c.id]);
      continue;                                        // encore loin : rien à signaler
    }
    const cle = `${seuil}:${String(c.not_after).slice(0, 10)}`;
    if (c.expiry_alert_key === cle) continue;          // palier déjà signalé
    const r = await _certAlert({
      to: await _certAllRecipients(c.id, c.notify_email),
      level: jours <= 3 ? "error" : "warn",
      subject: jours < 0 ? `[certfleet] Certificat EXPIRÉ — ${c.common_name}`
                         : `[certfleet] Certificat à expiration dans ${jours} j — ${c.common_name}`,
      intro: jours < 0 ? "Ce certificat est expiré et n'a pas été renouvelé."
                       : `Ce certificat expire dans ${jours} jour(s) et n'a pas encore été renouvelé.`,
      rows: [["Certificat", c.common_name], ["Expire le", String(c.not_after).slice(0, 10)],
             ["Renouvellement automatique", c.auto_renew ? "activé" : "DÉSACTIVÉ"]],
      hint: c.auto_renew ? "Le renouvellement automatique est actif : si rien ne se passe, consultez les journaux du service."
                         : "Le renouvellement automatique est désactivé : ce certificat doit être renouvelé à la main."
    });
    if (r.sent) await query("UPDATE cert_certificates SET expiry_alert_key=$2 WHERE id=$1", [c.id, cle]);
  }
}

// La sonde voit déjà qu'un service sert autre chose que le certificat déployé :
// c'est exactement le cas « écrit sur la cible mais jamais rechargé ».
const _STATUTS_ALERTE = {
  unreachable: "Service injoignable : impossible de vérifier le certificat servi.",
  mismatch: "Le certificat servi n'est pas celui qui a été déployé.",
  flapping: "Des certificats différents sont servis selon les requêtes (réplicas incohérents).",
  expired: "Le certificat servi est expiré."
};
async function _certEndpointAlert(ep, r) {
  if (!_STATUTS_ALERTE[r.status]) {
    if (ep.alert_key) await query("UPDATE cert_endpoints SET alert_key=NULL WHERE id=$1", [ep.id]);
    return;                                            // retour à la normale
  }
  const cle = `${r.status}:${String(r.fingerprint_sha256 || "").slice(0, 16)}`;
  if (ep.alert_key === cle) return;                    // déjà signalé, on ne harcèle pas
  const cert = ep.certificate_id
    ? (await query("SELECT common_name, notify_email FROM cert_certificates WHERE id=$1", [ep.certificate_id])).rows[0]
    : null;
  const tos = ep.certificate_id ? await _certAllRecipients(ep.certificate_id, cert?.notify_email) : [];
  const a = await _certAlert({
    to: [ep.notify_email, ...tos],
    level: r.status === "expired" ? "error" : "warn",
    subject: `[certfleet] Anomalie TLS — ${ep.label || ep.host}`,
    intro: _STATUTS_ALERTE[r.status],
    rows: [["Endpoint", `${ep.host}:${ep.port || 443}`],
           ["Certificat attendu", cert?.common_name || "—"],
           ["Statut", r.status],
           ["Échéance servie", r.not_after ? String(r.not_after).slice(0, 10) : "—"]],
    hint: r.status === "mismatch"
      ? "Le déploiement a bien écrit le certificat, mais le service ne l'a pas rechargé."
      : "Vérifiez le service, puis relancez le déploiement si nécessaire."
  });
  if (a.sent) await query("UPDATE cert_endpoints SET alert_key=$2 WHERE id=$1", [ep.id, cle]);
}

// ═════════════════════════════════════════════
// PAIRE HA (HAProxy / ALOHA) — on sert le nœud passif d'abord, l'actif ensuite.
// Deux règles, et la seconde compte autant que la première :
//   1. le backup reçoit le certificat en premier, le master après un délai ;
//   2. si le backup échoue, le master n'est PAS touché — sinon on casserait le
//      nœud encore sain par-dessus celui qui vient de tomber.
// ═════════════════════════════════════════════
const _haRole = t => String(t?.params?.ha_role || "").toLowerCase();
export function _haDelayMin(t) {
  const v = parseInt(t?.params?.ha_delay_min, 10);
  return Number.isFinite(v) && v >= 0 ? Math.min(v, 1440) : 10;
}

// backup d'abord, nœuds isolés ensuite, master en dernier — l'ordre manuel
// (deploy_order) reste respecté à l'intérieur de chaque groupe.
export function _ordreHa(tgts) {
  const rang = t => (_haRole(t) === "backup" ? 0 : _haRole(t) === "master" ? 2 : 1);
  return tgts.slice().sort((a, b) =>
    rang(a) - rang(b) || (a.deploy_order || 0) - (b.deploy_order || 0) || a.id - b.id);
}

// Déploiement sur toutes les cibles, en respectant la séquence HA.
async function _deployStaged(cert, tgts, actor) {
  const ordonnees = _ordreHa(tgts);
  const masters = ordonnees.filter(t => _haRole(t) === "master");
  const immediates = ordonnees.filter(t => _haRole(t) !== "master");
  const results = [], differes = [];

  let backupsKo = 0, backupsOk = 0;
  for (const t of immediates) {
    try {
      results.push({ target_id: t.id, ...(await _deployToTarget(cert, t, actor)) });
      if (_haRole(t) === "backup") backupsOk++;
    } catch (e) {
      results.push({ target_id: t.id, error: e.message });
      if (_haRole(t) === "backup") backupsKo++;
      await _certAlert({ to: [t.notify_email, cert.notify_email],
        subject: `[certfleet] ÉCHEC de déploiement — ${cert.common_name} → ${t.name || t.type}`,
        intro: "Le déploiement du certificat sur cette cible a échoué.",
        rows: [["Certificat", cert.common_name], ["Cible", `${t.name || "#" + t.id} (${t.type})`],
               ["Rôle HA", _haRole(t) || "—"], ["Erreur", e.message]],
        hint: _haRole(t) === "backup"
          ? "Le master ne sera PAS déployé tant que le backup n'aura pas abouti : le nœud actif reste intact."
          : "Relancez le déploiement après correction." });
    }
  }

  for (const t of masters) {
    if (backupsKo > 0) {                       // garde-fou principal
      results.push({ target_id: t.id, skipped: "backup en échec" });
      await _certAlert({ to: [t.notify_email, cert.notify_email],
        subject: `[certfleet] Déploiement du master SUSPENDU — ${cert.common_name}`,
        intro: "Le déploiement sur le nœud master a été volontairement suspendu.",
        rows: [["Certificat", cert.common_name], ["Master", `${t.name || "#" + t.id} (${t.type})`],
               ["Motif", `${backupsKo} nœud(s) backup en échec`]],
        hint: "Le nœud actif conserve son certificat en cours. Corrigez le backup, puis relancez le déploiement." });
      continue;
    }
    const delai = _haDelayMin(t);
    if (!backupsOk || delai === 0) {           // pas de backup dans la paire : rien à attendre
      try { results.push({ target_id: t.id, ...(await _deployToTarget(cert, t, actor)) }); }
      catch (e) { results.push({ target_id: t.id, error: e.message }); }
      continue;
    }
    const due = new Date(Date.now() + delai * 60000);
    await query(`INSERT INTO cert_deploy_queue(certificate_id, target_id, due_at, reason)
      VALUES ($1,$2,$3,$4)`, [cert.id, t.id, due, actor]);
    differes.push({ target_id: t.id, due_at: due, delay_min: delai });
    results.push({ target_id: t.id, scheduled_at: due, delay_min: delai });
  }
  return { results, differes };
}

// Cron court : sert les masters dont le délai est écoulé.
export function startCertDeployQueueCron(intervalMin = 2) {
  const run = async () => {
    try {
      await ensureCertSchema();
      const due = (await query(`SELECT * FROM cert_deploy_queue
        WHERE status='pending' AND due_at <= now() ORDER BY due_at LIMIT 20`)).rows;
      for (const q of due) {
        const cert = (await query("SELECT * FROM cert_certificates WHERE id=$1", [q.certificate_id])).rows[0];
        const t = (await query("SELECT * FROM cert_targets WHERE id=$1 AND enabled=true", [q.target_id])).rows[0];
        if (!cert || !t) {
          await query("UPDATE cert_deploy_queue SET status='cancelled', done_at=now(), error=$2 WHERE id=$1",
            [q.id, "certificat ou cible absent / désactivé"]);
          continue;
        }
        try {
          await _deployToTarget(cert, t, (q.reason || "auto") + " (master HA)");
          await query("UPDATE cert_deploy_queue SET status='done', done_at=now() WHERE id=$1", [q.id]);
          console.log(`[certQueue] master déployé : ${cert.common_name} → ${t.name || t.id}`);
          await _certAlert({ to: [t.notify_email, cert.notify_email], level: "ok",
            subject: `[certfleet] Master HA déployé — ${cert.common_name}`,
            intro: "Le nœud master a reçu le certificat après le délai de sécurité.",
            rows: [["Certificat", cert.common_name], ["Master", `${t.name || "#" + t.id} (${t.type})`],
                   ["Échéance", String(cert.not_after).slice(0, 10)]],
            hint: "La paire est désormais à jour sur les deux nœuds." });
        } catch (e) {
          await query("UPDATE cert_deploy_queue SET status='error', done_at=now(), error=$2 WHERE id=$1",
            [q.id, e.message]);
          console.warn(`[certQueue] échec master ${q.target_id}:`, e.message);
          await _certAlert({ to: [t.notify_email, cert.notify_email],
            subject: `[certfleet] ÉCHEC sur le master HA — ${cert.common_name}`,
            intro: "Le backup a bien été mis à jour, mais le déploiement sur le master a échoué.",
            rows: [["Certificat", cert.common_name], ["Master", `${t.name || "#" + t.id} (${t.type})`],
                   ["Erreur", e.message]],
            hint: "La paire est désynchronisée : backup à jour, master sur l'ancien certificat." });
        }
      }
    } catch (e) { console.warn("[certQueue]", e.message); }
  };
  setTimeout(run, 90000);
  setInterval(run, intervalMin * 60000);
  console.log(`[certQueue] cron actif (toutes les ${intervalMin} min)`);
}

export function startCertMonitorCron(intervalMin = 360) {
  const run = async () => {
    try {
      await ensureCertSchema();
      const eps = (await query(`SELECT e.*, c.fingerprint_sha256 AS expected_fpr FROM cert_endpoints e
        LEFT JOIN cert_certificates c ON c.id=e.certificate_id WHERE e.enabled=true`)).rows;
      for (const ep of eps) {
        const pr = await _applyProbe(ep).catch(() => null);
        if (pr) await _certEndpointAlert(ep, pr).catch(e => console.warn("[certMonitor] alerte:", e.message));
      }
      if (eps.length) console.log(`[certMonitor] ${eps.length} endpoint(s) sondé(s)`);
    } catch (e) { console.warn("[certMonitor]", e.message); }
  };
  setTimeout(run, 60 * 1000);                    // 1er passage 1 min après le boot
  setInterval(run, safeIntervalMs(intervalMin, "certMonitor"));
  console.log(`[certMonitor] cron actif (toutes les ${intervalMin} min)`);
}

// ── Cron d'AUTO-RENOUVELLEMENT : renouvelle les certs dus (auto_renew) puis
//    redéploie automatiquement sur toutes les cibles agent + reload. ──
export function startCertRenewCron(intervalMin = 720) {
  const run = async () => {
    try {
      await ensureCertSchema();
      const certs = (await query("SELECT * FROM cert_certificates WHERE auto_renew=true AND leaf_pem IS NOT NULL AND not_after IS NOT NULL AND source='acme'")).rows;
      for (const cert of certs) {
        const notAfter = new Date(cert.not_after).getTime();
        const notBefore = cert.not_before ? new Date(cert.not_before).getTime() : (notAfter - 90 * 86400000);
        const total = Math.max(1, notAfter - notBefore);
        const remaining = notAfter - Date.now();
        const pct = (cert.renew_before_pct || 33) / 100;
        if (remaining > total * pct) continue;                 // pas encore l'heure de renouveler
        if (_issuing.has(cert.id)) continue;
        const env = (cert.acme_directory && cert.acme_directory.includes("staging")) ? "staging" : "production";
        _issuing.add(cert.id);
        try {
          console.log(`[certRenew] renouvellement ${cert.common_name} (reste ${Math.round(remaining / 86400000)} j, seuil ${cert.renew_before_pct || 33}%)`);
          const r = await _issueCert(cert.id, env, "auto-renew");
          if (r.ok) {
            const fresh = (await query("SELECT * FROM cert_certificates WHERE id=$1", [cert.id])).rows[0];
            const tgts = (await query("SELECT * FROM cert_targets WHERE certificate_id=$1 AND enabled=true ORDER BY deploy_order, id", [cert.id])).rows;
            // Sequence HA : backup d'abord, master apres le delai (et jamais si
            // le backup a echoue). _deployStaged alerte deja sur les echecs.
            const { results, differes } = await _deployStaged(fresh, tgts, "auto-renew");
            const parId = new Map(tgts.map(t => [t.id, t]));
            let ok = 0;
            for (const r of results) {
              const t = parId.get(r.target_id);
              if (!t || r.error || r.skipped) continue;
              if (r.scheduled_at) {
                await _certAlert({ to: [t.notify_email, cert.notify_email], level: "ok",
                  subject: `[certfleet] Certificat renouvelé — master en attente — ${cert.common_name}`,
                  intro: "Le certificat a été renouvelé. Le nœud master sera servi après le délai de sécurité.",
                  rows: [["Certificat", cert.common_name], ["Master", `${t.name || "#" + t.id} (${t.type})`],
                         ["Déploiement prévu", new Date(r.scheduled_at).toLocaleString("fr-FR")],
                         ["Délai", `${r.delay_min} min après le backup`]],
                  hint: "Vous recevrez une confirmation une fois le master déployé." });
                continue;
              }
              ok++;
              await _certAlert({ to: [t.notify_email, cert.notify_email], level: "ok",
                subject: `[certfleet] Certificat renouvelé et déployé — ${cert.common_name}`,
                intro: "Le certificat a été renouvelé automatiquement et redéployé sur cette cible.",
                rows: [["Certificat", cert.common_name], ["Cible", `${t.name || "#" + t.id} (${t.type})`],
                       ["Rôle HA", _haRole(t) || "—"],
                       ["Nouvelle échéance", String(fresh.not_after).slice(0, 10)]],
                hint: "Aucune action de votre part n'est nécessaire." });
            }
            console.log(`[certRenew] ${cert.common_name} renouvelé → ${ok}/${tgts.length} cible(s) redéployée(s)`
              + (differes.length ? `, ${differes.length} master(s) différé(s)` : ""));
          } else {
            console.warn(`[certRenew] ${cert.common_name} : échec émission (${r.error})`);
            await _certAlert({ to: await _certAllRecipients(cert.id, cert.notify_email),
              subject: `[certfleet] ÉCHEC de renouvellement — ${cert.common_name}`,
              intro: "Le renouvellement automatique de ce certificat a échoué.",
              rows: [["Certificat", cert.common_name], ["Erreur", r.error || "inconnue"],
                     ["Expire le", String(cert.not_after).slice(0, 10)],
                     ["Jours restants", String(Math.round(remaining / 86400000))]],
              hint: "Le cron réessaiera au prochain passage. Si l'échec persiste, corrigez la cause avant l'échéance." });
          }
        } catch (e) { console.warn("[certRenew]", cert.common_name, e.message); }
        finally { _issuing.delete(cert.id); }
      }
      await _certExpiryWatch().catch(e => console.warn("[certRenew] veille expiration:", e.message));
    } catch (e) { console.warn("[certRenew]", e.message); }
  };
  setTimeout(run, 120000);                  // 1er passage 2 min après le boot
  setInterval(run, safeIntervalMs(intervalMin, "certRenew"));
  console.log(`[certRenew] cron actif (toutes les ${intervalMin} min)`);
}

export default router;
