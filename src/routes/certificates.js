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
// mode : 'agent' (via agent ADM Linux/Windows) | 'api' (connecteur push) | 'k8s' (monitoring)
export const TARGET_TYPES = [
  { type: "k8s_secret",   label: "Kubernetes (Secret TLS)", mode: "k8s",   icon: "☸️",
    note: "Monitoring seul au lot 1 (cert-manager reste maître). Rollout restart ciblé plus tard.",
    fields: [ { key: "cluster", label: "Cluster", type: "text", required: true },
              { key: "namespace", label: "Namespace", type: "text", required: true },
              { key: "secret", label: "Nom du Secret", type: "text", required: true } ] },
  { type: "nginx",        label: "nginx", mode: "agent", icon: "🌐",
    note: "reload (jamais restart). fullchain + clé.",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin fullchain", type: "text", required: true, placeholder: "/etc/nginx/ssl/site.crt" },
              { key: "key_path", label: "Chemin clé", type: "text", required: true, placeholder: "/etc/nginx/ssl/site.key" },
              { key: "reload_cmd", label: "Commande reload", type: "text", default: "nginx -s reload" } ] },
  { type: "apache",       label: "Apache", mode: "agent", icon: "🪶",
    note: "reload (jamais restart).",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin cert", type: "text", required: true },
              { key: "key_path", label: "Chemin clé", type: "text", required: true },
              { key: "chain_path", label: "Chemin chaîne", type: "text" },
              { key: "reload_cmd", label: "Commande reload", type: "text", default: "apachectl graceful" } ] },
  { type: "haproxy",      label: "HAProxy", mode: "agent", icon: "🔀",
    note: "fullchain + clé CONCATÉNÉS dans un seul PEM.",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "pem_path", label: "Chemin PEM combiné", type: "text", required: true, placeholder: "/etc/haproxy/certs/site.pem" },
              { key: "reload_cmd", label: "Commande reload", type: "text", default: "systemctl reload haproxy" } ] },
  { type: "aloha",        label: "HAProxy ALOHA (appliance virtuelle)", mode: "api", icon: "🔀",
    note: "Appliance HAProxy ALOHA — push via la Data Plane API (port 5555, /v3). certfleet REMPLACE le PEM (fullchain+clé) d'un certificat DÉJÀ présent dans le storage (bouton « Lister » pour le nom exact) et demande un reload immédiat (force_reload). La création d'un nouveau certificat (POST multipart) n'est pas implémentée. Un appareil = une cible : pour une paire HA, créer deux cibles. ✅ Connecteur opérationnel.",
    fields: [ { key: "base_url", label: "URL Data Plane API", type: "text", required: true, placeholder: "http://lb-01.example.com:5555" },
              { key: "cert_name", label: "Nom du fichier certificat (storage ALOHA)", type: "text", required: true, placeholder: "exampleservicescom.pem" },
              { key: "username", label: "Utilisateur API (Basic Auth)", type: "text", required: true, placeholder: "admin" },
              { key: "password", label: "Mot de passe API", type: "password", required: true },
              { key: "insecure", label: "Ignorer la vérif TLS (API en HTTPS auto-signé)", type: "bool" } ] },
  { type: "caddy",        label: "Caddy", mode: "agent", icon: "🧱",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin cert", type: "text", required: true },
              { key: "key_path", label: "Chemin clé", type: "text", required: true },
              { key: "reload_cmd", label: "Commande reload", type: "text", default: "caddy reload" } ] },
  { type: "traefik",      label: "Traefik (fichier)", mode: "agent", icon: "🚦",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin cert", type: "text", required: true },
              { key: "key_path", label: "Chemin clé", type: "text", required: true } ] },
  { type: "glpi",         label: "GLPI (serveur web)", mode: "agent", icon: "🧰",
    note: "GLPI = appli web PHP servie par Apache/nginx : on dépose le cert sur le serveur web + reload.",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin du certificat (vhost)", type: "text", required: true, placeholder: "/etc/pki/tls/certs/glpi.crt" },
              { key: "key_path", label: "Chemin de la clé (vhost)", type: "text", required: true, placeholder: "/etc/pki/tls/private/glpi.key" },
              { key: "reload_cmd", label: "Reload serveur web", type: "text", default: "systemctl reload httpd" } ] },
  { type: "vsftpd",       label: "vsftpd", mode: "agent", icon: "📁",
    note: "vsftpd : rsa_cert_file + rsa_private_key_file (2 fichiers séparés) + restart.",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin du certificat (rsa_cert_file)", type: "text", required: true, placeholder: "/etc/ssl/certs/vsftpd.pem" },
              { key: "key_path", label: "Chemin de la clé (rsa_private_key_file)", type: "text", required: true, placeholder: "/etc/ssl/private/vsftpd.key" },
              { key: "reload_cmd", label: "Commande", type: "text", default: "systemctl restart vsftpd" } ] },
  { type: "servu",        label: "Serv-U (FTP)", mode: "agent", icon: "📂",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "cert_path", label: "Chemin cert (.crt)", type: "text", required: true },
              { key: "key_path", label: "Chemin clé (.key)", type: "text", required: true },
              { key: "chain_path", label: "Chemin chaîne / CA (.pem)", type: "text", placeholder: "/usr/local/Serv-U/pki/2025/letsencrypt-chain.pem" } ] },
  { type: "iis",          label: "IIS (Windows)", mode: "agent", icon: "🪟",
    note: "Rebind par thumbprint + nettoyage du store (sinon il gonfle).",
    fields: [ { key: "agent_id", label: "Agent Windows", type: "agent", required: true },
              { key: "site", label: "Site IIS", type: "text", required: true, placeholder: "Default Web Site" },
              { key: "binding", label: "Binding", type: "text", default: "https :443:" },
              { key: "store", label: "Store", type: "text", default: "My" } ] },
  { type: "exchange",     label: "Exchange", mode: "agent", icon: "📧",
    note: "Enable-ExchangeCertificate -Services IIS,SMTP,IMAP,POP -Force. Receive Connectors : TlsCertificateName au format <I>issuer<S>subject (JAMAIS le thumbprint). Purger les anciens.",
    fields: [ { key: "agent_id", label: "Agent Windows", type: "agent", required: true },
              { key: "services", label: "Services", type: "text", default: "IIS,SMTP,IMAP,POP" },
              { key: "update_receive_connectors", label: "MAJ Receive Connectors (TlsCertificateName)", type: "bool", default: true },
              { key: "purge_old", label: "Purger les anciens certs", type: "bool", default: true } ] },
  { type: "rds_gateway",  label: "Passerelle RDS (RD Gateway)", mode: "agent", icon: "🪟",
    note: "Windows : PFX importé dans LocalMachine\\My + lié au rôle RD Gateway. Agent Windows requis.",
    fields: [ { key: "agent_id", label: "Agent Windows", type: "agent", required: true },
              { key: "deployment", label: "Type (standalone | rds-deployment)", type: "text", default: "standalone" },
              { key: "connection_broker", label: "Connection Broker (si rds-deployment)", type: "text" },
              { key: "pfx_password_ref", label: "Réf. mot de passe PFX (secret, optionnel)", type: "text" } ] },
  { type: "java_keystore", label: "Java Keystore (PKCS12)", mode: "agent", icon: "☕",
    note: "Alias + redémarrage applicatif quasi toujours nécessaire.",
    fields: [ { key: "agent_id", label: "Agent", type: "agent", required: true },
              { key: "keystore_path", label: "Chemin keystore", type: "text", required: true },
              { key: "alias", label: "Alias", type: "text", required: true },
              { key: "storepass_ref", label: "Réf. mot de passe (secret)", type: "text" },
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
  "Sur le serveur CIBLE, installer l'agent certfleet NATIF : ouvre IT › ADM, copie la commande d'enrôlement (curl …/api/adm/install.sh | sudo … bash) et exécute-la EN ROOT sur le serveur. Elle installe l'agent + le helper de certificat + la règle sudoers AUTOMATIQUEMENT (tu n'as pas à poser le helper à la main).",
  "Attends ~1 min puis vérifie que le serveur apparaît dans IT › ADM (dernier contact récent). Il apparaîtra alors dans la liste déroulante « Agent » ci-dessus (par hostname).",
  "IMPORTANT : le helper cert est TOUJOURS en NOPASSWD, même si l'agent a été installé en mode sécurisé (SUDO_SECURE=1). Le déploiement/renouvellement de certificat est donc 100 % non-interactif — jamais de mot de passe. Le mot de passe sudo (mode sécurisé) ne concerne QUE les mises à jour CVE (dnf), pas les certs.",
  "Dépannage seulement (si l'agent est là mais le helper manque) : helper root /usr/local/bin/certfleet-cert-install + sudoers NOPASSWD. Commandes manuelles dans l'onglet « Types de cible » → encadré « Prérequis cible agent ». Sans le helper : l'agent écrit le cert mais NE recharge PAS le service.",
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
      reload_cmd: "apachectl graceful (recharge sans couper les connexions)" },
    verify: "curl -vI https://monsite  → regarde la date d'expiration.",
    gotcha: "Apache récent accepte le fullchain dans SSLCertificateFile ; sur très vieux Apache, la chaîne va dans SSLCertificateChainFile." },
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
    gotcha: "Traefik provider « file » surveille les fichiers → recharge automatique, pas de commande reload nécessaire. Laisse le reload vide." },
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
    prepare: ["Installe l'agent certfleet WINDOWS sur le serveur (IT › ADM, section agent Windows).", "L'agent Windows construit le PFX localement à partir du cert+clé (la clé privée ne transite jamais en PFX).", "Compte de service avec droits d'import cert + gestion IIS."],
    fields: { agent_id: "Le serveur Windows/IIS.",
      site: "Nom du site IIS. Ex : Default Web Site",
      binding: "Binding HTTPS à mettre à jour. Ex : https :443:",
      store: "Magasin de certificats. Ex : My (LocalMachine\\My)" },
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
    prepare: ["Installer l'agent certfleet WINDOWS sur le serveur RD Gateway (IT › ADM, section agent Windows).",
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
      storepass_ref: "Référence du mot de passe du keystore (secret).",
      restart_cmd: "Commande pour redémarrer l'appli (ex : systemctl restart montomcat)" },
    verify: "keytool -list -keystore keystore.p12 -alias monsite ; puis test TLS sur le port de l'appli.",
    gotcha: "La cible la plus douloureuse : format PKCS12, l'appli doit être redémarrée pour relire le keystore. Attention au mot de passe du keystore (storepass)." },
  uag: { what: "Pousse le certificat via l'API d'admin de VMware Horizon / UAG (Unified Access Gateway). PAS d'agent — connecteur API (lot suivant).",
    prepare: ["Aucun agent à installer (appliance durcie).", "Créer un accès API admin sur l'UAG (port 9443) + stocker les identifiants comme secret dans certfleet."],
    fields: { base_url: "URL admin de l'UAG. Ex : https://uag.exemple:9443", cred_ref: "Référence du secret (login/mdp API admin UAG)." },
    verify: "Ouvre l'URL de l'UAG dans un navigateur → cadenas → nouveau cert.",
    gotcha: "Connecteur API pas encore construit (lot suivant). L'UAG attend un cert+clé au format PEM via son API REST." },
  f5: { what: "Pousse le cert via l'API iControl REST du F5 BIG-IP et l'associe au Client SSL profile. Connecteur API (lot suivant).",
    prepare: ["Compte API sur le F5 (iControl REST) + secret dans certfleet."],
    fields: { base_url: "URL iControl REST. Ex : https://f5-mgmt", profile: "Nom du Client SSL profile à mettre à jour.", cred_ref: "Secret (identifiants API F5)." },
    verify: "openssl s_client -connect vip:443", gotcha: "Connecteur API à construire (lot suivant)." },
  checkpoint: { what: "Pousse le cert via l'API Check Point. Connecteur API (lot suivant).",
    prepare: ["Accès API Management Check Point + secret."],
    fields: { base_url: "URL API.", cred_ref: "Secret (identifiants API)." },
    verify: "—", gotcha: "Connecteur API à construire (lot suivant)." },
  api_generic: { what: "Pousse le cert via l'API HTTP d'une appliance FERMÉE, sur laquelle on ne peut PAS installer l'agent certfleet (ex. ECS Dell, Harbor). Connecteur API (lot suivant). ⚠️ Zabbix, Graylog, NetBox tournent sur Linux avec agent → NE PAS utiliser ce type : passe par une cible Apache/nginx (agent), comme GLPI.",
    prepare: ["Créer un token/compte API sur l'appliance + le stocker comme secret."],
    fields: { base_url: "URL de l'API d'upload du cert.", method: "Méthode HTTP (PUT/POST).", cred_ref: "Secret (token/identifiants)." },
    verify: "Vérifie dans l'admin de l'appliance.", gotcha: "Chaque appliance a son API propre — connecteur dédié à construire (lot suivant)." },
  k8s_secret: { what: "MONITORING seul dans ce lot : cert-manager reste maître de l'émission sur K8s. certfleet surveille l'expiration (via un endpoint monitoré) et pourra faire un rollout ciblé plus tard.",
    prepare: ["Rien à installer côté certfleet pour la surveillance.", "Pour surveiller le cert servi : ajoute l'URL du service dans l'onglet Monitoring."],
    fields: { cluster: "Nom du cluster (libellé).", namespace: "Namespace du Secret TLS.", secret: "Nom du Secret TLS (type kubernetes.io/tls)." },
    verify: "kubectl -n <ns> get secret <secret> -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -enddate",
    gotcha: "Ne remplace pas cert-manager. Mettre à jour le Secret ne suffit pas : les pods qui montent le cert en volume gardent l'ancien → rollout restart nécessaire (lot suivant)." },
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
function _httpRequest(method, urlStr, { headers = {}, body = null, insecure = false, timeout = 20000 } = {}) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(urlStr); } catch { return reject(new Error("URL invalide: " + urlStr)); }
    const isHttps = u.protocol === "https:";
    const lib = isHttps ? https : http;
    const opts = {
      method, hostname: u.hostname, port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search, headers: { ...headers }, timeout,
    };
    if (isHttps && insecure) opts.rejectUnauthorized = false;
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

// Chiffre les secrets d'une cible avant stockage (params jsonb). Le mot de passe API
// (ALOHA…) est stocké chiffré (password_enc) ; jamais en clair dans params.
async function _encTargetParams(params) {
  const p = { ...(params || {}) };
  if (p.password != null && p.password !== "") {
    p.password_enc = await vaultEncrypt(String(p.password));
  }
  delete p.password; // ne jamais persister le clair
  return p;
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
    const r = await query(`INSERT INTO cert_targets(certificate_id, name, type, agent_id, params, deploy_order, post_hook, verify, enabled)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
      [cid, _str(b.name), _str(b.type), _str(b.agent_id),
       JSON.stringify(params), _int(b.deploy_order) || 0, _str(b.post_hook),
       JSON.stringify(b.verify || {}), b.enabled !== false]);
    res.status(201).json({ ok: true, id: r.rows[0].id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
router.put("/targets/:tid", async (req, res) => {
  try {
    const tid = _int(req.params.tid); const b = req.body || {};
    const params = await _encTargetParams(b.params);
    // Si aucun nouveau mot de passe fourni, conserver le password_enc existant
    if (!params.password_enc) {
      const old = (await query("SELECT params FROM cert_targets WHERE id=$1", [tid])).rows[0]?.params || {};
      if (old.password_enc) params.password_enc = old.password_enc;
    }
    await query(`UPDATE cert_targets SET name=$2, type=COALESCE($3,type), agent_id=$4,
      params=$5, deploy_order=$6, post_hook=$7, verify=$8, enabled=$9 WHERE id=$1`,
      [tid, _str(b.name), _str(b.type), _str(b.agent_id), JSON.stringify(params),
       _int(b.deploy_order) || 0, _str(b.post_hook), JSON.stringify(b.verify || {}), b.enabled !== false]);
    res.json({ ok: true });
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

async function _deployToTarget(cert, t, actor) {
  if (!cert.leaf_pem || !cert.private_key_enc) throw new Error("Certificat non émis — émets-le d'abord");
  const typeDef = TARGET_TYPES.find(x => x.type === t.type);
  if (typeDef && typeDef.mode === "api" && t.type === "aloha") return _deployAloha(cert, t, actor);
  if (!typeDef || typeDef.mode !== "agent") throw new Error(`Déploiement « ${typeDef?.mode || t.type} » pas encore supporté (lot suivant)`);
  if (!t.agent_id) throw new Error("Cible sans agent (choisis un agent enrôlé)");
  const ag = (await query("SELECT pubkey FROM agents WHERE agent_id=$1", [t.agent_id])).rows[0];
  if (!ag?.pubkey) throw new Error("Agent sans clé publique (réenrôle l'agent)");
  const params = t.params || {};
  const cert_path = params.cert_path || params.pem_path;
  const key_path = params.key_path || params.pem_path;
  if (!cert_path || !key_path) throw new Error("Paramètres cert_path/key_path manquants sur la cible");

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
  const payload = {
    cert_pem: fullchain, cert_path, key_path,
    ...(chain_path ? { chain_path, chain_pem: (cert.chain_pem || "").trim() + "\n" } : {}),
    key_iv: iv.toString("hex"),
    aeskey_enc: aesKeyEnc.toString("base64"),
    key_cipher: keyCipher.toString("base64"),
    reload_cmd: params.reload_cmd || "",
  };
  const cmd = (await query(
    "INSERT INTO commands (agent_id, action, kind, payload, status, proposed_by, approved_by) VALUES ($1,'deploy','cert',$2,'approved',$3,$3) RETURNING id",
    [t.agent_id, JSON.stringify(payload), actor]
  )).rows[0];
  const dep = (await query(
    "INSERT INTO cert_deployments (certificate_id, target_id, status, adm_command_id, log) VALUES ($1,$2,'pending',$3,$4) RETURNING id",
    [cert.id, t.id, cmd.id, `Commande cert-deploy → ${t.agent_id} : ${cert_path}`]
  )).rows[0];
  return { command_id: cmd.id, deployment_id: dep.id, agent_id: t.agent_id, cert_path };
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
    const results = [];
    for (const t of tgts) { try { results.push({ target_id: t.id, ...(await _deployToTarget(cert, t, actor)) }); } catch (e) { results.push({ target_id: t.id, error: e.message }); } }
    res.json({ ok: true, results });
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

export function startCertMonitorCron(intervalMin = 360) {
  const run = async () => {
    try {
      await ensureCertSchema();
      const eps = (await query(`SELECT e.*, c.fingerprint_sha256 AS expected_fpr FROM cert_endpoints e
        LEFT JOIN cert_certificates c ON c.id=e.certificate_id WHERE e.enabled=true`)).rows;
      for (const ep of eps) { await _applyProbe(ep).catch(() => {}); }
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
            let ok = 0;
            for (const t of tgts) { try { await _deployToTarget(fresh, t, "auto-renew"); ok++; } catch (e) { console.warn(`[certRenew] deploy cible ${t.id} (${t.type}):`, e.message); } }
            console.log(`[certRenew] ${cert.common_name} renouvelé → ${ok}/${tgts.length} cible(s) redéployée(s)`);
          } else {
            console.warn(`[certRenew] ${cert.common_name} : échec émission (${r.error})`);
          }
        } catch (e) { console.warn("[certRenew]", cert.common_name, e.message); }
        finally { _issuing.delete(cert.id); }
      }
    } catch (e) { console.warn("[certRenew]", e.message); }
  };
  setTimeout(run, 120000);                  // 1er passage 2 min après le boot
  setInterval(run, safeIntervalMs(intervalMin, "certRenew"));
  console.log(`[certRenew] cron actif (toutes les ${intervalMin} min)`);
}

export default router;
