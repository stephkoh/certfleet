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
import { requireAuth } from "../auth.js";

const router = express.Router();
const AGENT_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "agent");

// ── Distribution des scripts (public : ils ne contiennent aucun secret) ──
function sendScript(res, name, type = "text/x-shellscript; charset=utf-8") {
  const f = path.join(AGENT_DIR, name);
  if (!fs.existsSync(f)) return res.status(404).send("script introuvable");
  res.type(type);
  res.send(fs.readFileSync(f, "utf8"));
}
router.get("/agent.sh", (_req, res) => sendScript(res, "certfleet-agent.sh"));
router.get("/cert-install.sh", (_req, res) => sendScript(res, "certfleet-cert-install"));

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
      `INSERT INTO agents (agent_id, token, hostname, fqdn, ip, os, os_version, kernel, arch, agent_version, pubkey, sudo_mode, last_seen)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())
       ON CONFLICT (agent_id) DO UPDATE SET
         hostname=EXCLUDED.hostname, fqdn=EXCLUDED.fqdn, ip=EXCLUDED.ip, os=EXCLUDED.os,
         os_version=EXCLUDED.os_version, kernel=EXCLUDED.kernel, arch=EXCLUDED.arch,
         agent_version=EXCLUDED.agent_version,
         pubkey=COALESCE(EXCLUDED.pubkey, agents.pubkey),
         sudo_mode=COALESCE(EXCLUDED.sudo_mode, agents.sudo_mode), last_seen=now()`,
      [b.agent_id, token, b.hostname || null, b.fqdn || null, b.ip || null, b.os || null,
       b.os_version || null, b.kernel || null, b.arch || null, b.agent_version || null,
       b.pubkey || null, b.sudo_mode || null]
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
      `SELECT agent_id, hostname, fqdn, ip, os, os_version, arch, agent_version, last_seen,
              (last_seen > now() - interval '10 minutes') AS online
         FROM agents ORDER BY hostname NULLS LAST, agent_id`);
    res.json({ agents: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete("/:agentId", requireAuth, async (req, res) => {
  try {
    await query("DELETE FROM agents WHERE agent_id=$1", [req.params.agentId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

export default router;
