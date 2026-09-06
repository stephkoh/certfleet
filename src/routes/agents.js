// ═══════════════════════════════════════════════════════════════════
// routes/agents.js — enrôlement des agents et file de commandes
//
// Modèle PULL : le hub n'ouvre JAMAIS de connexion vers les serveurs cibles
// et ne détient aucun identifiant sur eux. C'est l'agent qui interroge le hub.
// Conséquence pratique : rien à ouvrir dans le pare-feu vers vos serveurs.
// ═══════════════════════════════════════════════════════════════════
import express from "express";
import crypto from "node:crypto";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { query } from "../db.js";
import { requireAuth, requireRole, audit } from "../auth.js";

const router = express.Router();
const AGENT_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "agent");

// ── Distribution des scripts (public : ils ne contiennent aucun secret) ──
function sendScript(res, name, type = "text/x-shellscript; charset=utf-8") {
  const f = path.join(AGENT_DIR, name);
  if (!fs.existsSync(f)) return res.status(404).send("script introuvable");
  res.type(type);
  res.send(fs.readFileSync(f, "utf8"));
}
const PS = "text/plain; charset=utf-8";   // PowerShell : servi en texte brut

router.get("/agent.sh", (_req, res) => sendScript(res, "certfleet-agent.sh"));
router.get("/cert-install.sh", (_req, res) => sendScript(res, "certfleet-cert-install"));
router.get("/agent.ps1", (_req, res) => sendScript(res, "certfleet-agent.ps1", PS));

// ── Installateurs clés en main ──
// Le jeton d'enrôlement est inséré dans le script généré : ces deux routes sont
// donc les seules du fichier à exiger une authentification d'administrateur.
// L'URL du hub est déduite de la requête, pour que la commande affichée dans
// l'interface soit directement copiable.
function hubUrl(req) {
  const proto = String(req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0];
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

// L'appelant s'authentifie avec le JETON D'ENRÔLEMENT lui-même, pas avec une
// session : la commande est copiée depuis l'interface puis collée sur un
// serveur qui, lui, n'a aucune session. Posséder ce jeton est précisément le
// droit d'enrôler une machine — c'est donc le bon secret ici.
async function requireEnrollToken(req, res, next) {
  const expected = await getEnrollToken();
  if (!expected) {
    return res.status(503).type("text/plain").send("# Aucun jeton d'enrôlement configuré sur ce hub");
  }
  const h = String(req.headers.authorization || "");
  const given = h.startsWith("Bearer ") ? h.slice(7).trim() : String(req.query.token || "");

  const a = Buffer.from(given), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).type("text/plain").send("# Jeton d'enrôlement invalide");
  }
  req.enrollToken = expected;
  next();
}

router.get("/install.sh", requireEnrollToken, (req, res) => {
  res.type("text/x-shellscript; charset=utf-8");
  res.send(linuxInstaller(hubUrl(req), req.enrollToken));
});

router.get("/install.ps1", requireEnrollToken, (req, res) => {
  res.type(PS);
  res.send(windowsInstaller(hubUrl(req), req.enrollToken));
});

function linuxInstaller(url, token) {
  return `#!/usr/bin/env bash
# Installation de l'agent certfleet — à exécuter en root sur le serveur cible.
set -euo pipefail

HUB="${url}"
TOKEN="${token}"

for bin in curl openssl python3; do
  command -v "$bin" >/dev/null 2>&1 || { echo "[install] $bin requis mais absent" >&2; exit 1; }
done

echo "[install] téléchargement de l'agent"
curl -fsSL "$HUB/api/agents/agent.sh"        -o /usr/local/bin/certfleet-agent
curl -fsSL "$HUB/api/agents/cert-install.sh" -o /usr/local/bin/certfleet-cert-install
chmod 755 /usr/local/bin/certfleet-agent /usr/local/bin/certfleet-cert-install

# Le helper écrit dans /etc et recharge des services : il tourne en root via
# sudo, sur une liste blanche de commandes. C'est le seul privilège accordé.
echo "[install] règle sudoers pour le helper"
install -d -m 755 /etc/sudoers.d
cat > /etc/sudoers.d/certfleet-agent <<'SUDO'
Defaults!/usr/local/bin/certfleet-cert-install !requiretty
ALL ALL=(root) NOPASSWD: /usr/local/bin/certfleet-cert-install
SUDO
chmod 440 /etc/sudoers.d/certfleet-agent
visudo -cf /etc/sudoers.d/certfleet-agent >/dev/null

echo "[install] configuration"
install -d -m 750 /etc/certfleet-agent
cat > /etc/certfleet-agent/agent.conf <<CONF
CERTFLEET_URL="$HUB"
ENROLL_TOKEN="$TOKEN"
SUDO_MODE="nopasswd"
AUTO_UPDATE="1"
CONF
chmod 640 /etc/certfleet-agent/agent.conf

echo "[install] enrôlement"
/usr/local/bin/certfleet-agent enroll

echo "[install] minuterie"
/usr/local/bin/certfleet-agent install

# Le jeton d'enrôlement ne sert plus une fois l'agent connu du hub : le laisser
# sur le disque n'apporterait qu'un secret de plus à protéger.
sed -i 's/^ENROLL_TOKEN=.*/ENROLL_TOKEN=""/' /etc/certfleet-agent/agent.conf

/usr/local/bin/certfleet-agent run
echo "[install] terminé — l'agent apparaît maintenant dans l'onglet Agents"
`;
}

function windowsInstaller(url, token) {
  return `# Installation de l'agent certfleet — PowerShell 7+, en administrateur.
$ErrorActionPreference = "Stop"

$Hub   = "${url}"
$Token = "${token}"

if ($PSVersionTable.PSVersion.Major -lt 7) {
  throw "PowerShell 7 ou superieur est requis. Installez-le : winget install Microsoft.PowerShell"
}

$Dir = "$env:ProgramData\certfleet"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

Write-Host "[install] telechargement de l'agent"
Invoke-WebRequest -Uri "$Hub/api/agents/agent.ps1" -OutFile "$Dir\certfleet-agent.ps1" -UseBasicParsing

Write-Host "[install] configuration"
@{ CertfleetUrl = $Hub; EnrollToken = $Token } |
  ConvertTo-Json | Set-Content -Path "$Dirgent.conf.json" -Encoding utf8

# Le dossier contient la cle privee de l'agent : seuls SYSTEM et les
# administrateurs doivent pouvoir le lire.
icacls $Dir /inheritance:r /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" | Out-Null

Write-Host "[install] enrolement"
& "$Dir\certfleet-agent.ps1" enroll

Write-Host "[install] tache planifiee"
& "$Dir\certfleet-agent.ps1" install

# Le jeton d'enrolement ne sert plus une fois l'agent connu du hub.
$c = Get-Content "$Dirgent.conf.json" | ConvertFrom-Json
$c.EnrollToken = ""
$c | ConvertTo-Json | Set-Content -Path "$Dirgent.conf.json" -Encoding utf8

& "$Dir\certfleet-agent.ps1" run
Write-Host "[install] termine — l'agent apparait maintenant dans l'onglet Agents"
`;
}

// ── Enrôlement ──
// Protégé par un jeton partagé (settings.enroll_token), à régénérer si fuite.
async function getEnrollToken() {
  const r = await query("SELECT value FROM settings WHERE key='enroll_token'").catch(() => ({ rows: [] }));
  const v = r.rows[0]?.value;
  return typeof v === "string" ? v : (v?.token || null);
}

router.post("/enroll", async (req, res) => {
  try {
    const b = req.body || {};
    const et = await getEnrollToken();
    if (!et) return res.status(503).json({ error: "Enrôlement désactivé : aucun jeton configuré" });
    if (b.enroll_token !== et) return res.status(403).json({ error: "Jeton d'enrôlement invalide" });
    if (!b.agent_id) return res.status(400).json({ error: "agent_id requis" });

    // Un agent déjà connu conserve son jeton : réenrôler ne coupe pas le service.
    const existing = await query("SELECT token FROM agents WHERE agent_id=$1", [b.agent_id]);
    const token = existing.rows[0]?.token || crypto.randomBytes(24).toString("hex");

    await query(
      `INSERT INTO agents (agent_id, token, hostname, fqdn, ip, os, os_version, kernel, arch, agent_version, pubkey, sudo_mode, platform, last_seen)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now())
       ON CONFLICT (agent_id) DO UPDATE SET
         hostname=EXCLUDED.hostname, fqdn=EXCLUDED.fqdn, ip=EXCLUDED.ip, os=EXCLUDED.os,
         os_version=EXCLUDED.os_version, kernel=EXCLUDED.kernel, arch=EXCLUDED.arch,
         agent_version=EXCLUDED.agent_version,
         pubkey=COALESCE(EXCLUDED.pubkey, agents.pubkey),
         sudo_mode=COALESCE(EXCLUDED.sudo_mode, agents.sudo_mode),
         platform=COALESCE(EXCLUDED.platform, agents.platform), last_seen=now()`,
      [b.agent_id, token, b.hostname || null, b.fqdn || null, b.ip || null, b.os || null,
       b.os_version || null, b.kernel || null, b.arch || null, b.agent_version || null,
       b.pubkey || null, b.sudo_mode || null, b.platform || null]
    );
    res.json({ ok: true, token, poll_interval: Number(process.env.AGENT_POLL_INTERVAL || 60) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Authentification d'un agent (agent_id + token) ──
async function authAgent(req) {
  const b = req.body || {};
  const agent_id = b.agent_id || req.query.agent_id;
  const token = b.token || req.query.token || (req.headers["x-agent-token"] || "");
  if (!agent_id || !token) return null;
  const r = await query("SELECT agent_id, token FROM agents WHERE agent_id=$1", [agent_id]);
  const a = r.rows[0];
  if (!a) return null;
  const ba = Buffer.from(String(a.token)), bb = Buffer.from(String(token));
  if (ba.length !== bb.length || !crypto.timingSafeEqual(ba, bb)) return null;
  await query("UPDATE agents SET last_seen=now() WHERE agent_id=$1", [agent_id]).catch(() => {});
  return a;
}

// ── L'agent récupère ses commandes approuvées ──
router.get("/commands", async (req, res) => {
  try {
    const agent = await authAgent(req);
    if (!agent) return res.status(403).json({ error: "Agent non authentifié" });
    const r = await query(
      "SELECT id, action, kind, payload FROM commands WHERE agent_id=$1 AND status='approved' ORDER BY created_at LIMIT 10",
      [agent.agent_id]
    );
    if (r.rows.length) {
      await query("UPDATE commands SET status='running', updated_at=now() WHERE id = ANY($1::bigint[])",
        [r.rows.map(x => x.id)]);
    }
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── L'agent rend compte ──
router.post("/command-result", async (req, res) => {
  try {
    const agent = await authAgent(req);
    if (!agent) return res.status(403).json({ error: "Agent non authentifié" });
    const b = req.body || {};
    const st = Number(b.exit_code) === 0 ? "done" : "failed";
    await query(
      "UPDATE commands SET status=$1, result=$2, exit_code=$3, updated_at=now() WHERE id=$4 AND agent_id=$5",
      [st, String(b.result || "").slice(0, 10000), b.exit_code ?? null, Number(b.command_id), agent.agent_id]
    );
    // Répercute le résultat sur le déploiement lié, sinon la vue reste « en attente ».
    await query(
      `UPDATE cert_deployments SET status=$1, exit_code=$2, log=COALESCE(log,'') || E'\\n' || $3, finished_at=now()
         WHERE adm_command_id=$4 AND status IN ('pending','running')`,
      [st === "done" ? "success" : "failed", b.exit_code ?? null, String(b.result || "").slice(0, 4000), Number(b.command_id)]
    ).catch(() => {});
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Administration : lister les agents (utilisé par le formulaire de cible) ──
router.get("/", requireAuth, async (_req, res) => {
  try {
    const r = await query(
      `SELECT agent_id, hostname, fqdn, ip, os, os_version, arch, agent_version, platform,
              sudo_mode, pubkey IS NOT NULL AS has_key, created_at, last_seen,
              (last_seen > now() - interval '10 minutes') AS online
         FROM agents ORDER BY hostname NULLS LAST, agent_id`);
    res.json({ agents: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Jeton d'enrôlement ──
// Sans lui, aucun agent ne peut s'enrôler : c'est la première chose à faire
// dans une installation neuve. Réservé aux administrateurs.
router.get("/enroll-token", requireAuth, requireRole("admin"), async (_req, res) => {
  try {
    const token = await getEnrollToken();
    res.json({ token, configured: !!token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post("/enroll-token/rotate", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const token = crypto.randomBytes(24).toString("base64url");
    await query(
      `INSERT INTO settings(key, value, updated_at) VALUES('enroll_token', $1::jsonb, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [JSON.stringify(token)]
    );
    // Les agents déjà enrôlés gardent leur propre jeton : la rotation ne coupe
    // personne, elle empêche seulement de nouveaux enrôlements avec l'ancien.
    await audit(req, "agent.enroll_token_rotate");
    res.json({ token, configured: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete("/enroll-token", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    await query("DELETE FROM settings WHERE key='enroll_token'");
    await audit(req, "agent.enroll_token_disable");
    res.json({ ok: true, configured: false });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete("/:agentId", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    await query("DELETE FROM agents WHERE agent_id=$1", [req.params.agentId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Signal de vie ──
// L'agent rappelle périodiquement son identité machine. Authentifié par son
// propre jeton, pas par celui d'enrôlement : ce dernier est effacé du disque
// une fois l'installation terminée.
router.post("/heartbeat", async (req, res) => {
  try {
    const b = req.body || {};
    const token = req.headers["x-agent-token"] || b.token || "";
    if (!b.agent_id || !token) return res.status(400).json({ error: "agent_id et jeton requis" });

    const r = await query(
      `UPDATE agents SET hostname = COALESCE($3, hostname), fqdn = COALESCE($4, fqdn),
              ip = COALESCE($5, ip), os = COALESCE($6, os), os_version = COALESCE($7, os_version),
              kernel = COALESCE($8, kernel), arch = COALESCE($9, arch),
              agent_version = COALESCE($10, agent_version),
              sudo_mode = COALESCE($11, sudo_mode), platform = COALESCE($12, platform),
              last_seen = now()
        WHERE agent_id = $1 AND token = $2
        RETURNING agent_id`,
      [b.agent_id, token, b.hostname || null, b.fqdn || null, b.ip || null, b.os || null,
       b.os_version || null, b.kernel || null, b.arch || null, b.agent_version || null,
       b.sudo_mode || null, b.platform || null]
    );
    // Jeton invalide ou agent supprimé du hub : on le dit, l'agent saura qu'il
    // doit être réenrôlé plutôt que de battre dans le vide.
    if (!r.rows.length) return res.status(403).json({ error: "Agent inconnu ou jeton invalide" });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

export default router;
