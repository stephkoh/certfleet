// ═══════════════════════════════════════════════════════════════════
// certfleet — serveur
// Déploie vos certificats ACME là où cert-manager ne va pas.
// ═══════════════════════════════════════════════════════════════════
import express from "express";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { initSchema } from "./db.js";
import {
  requireAuth, requireRole, loginHandler, logoutHandler, meHandler,
  changeOwnPasswordHandler, ensureBootstrapAdmin, purgeExpiredSessions,
} from "./auth.js";
import certificatesRouter, {
  ensureCertSchema, startCertMonitorCron, startCertRenewCron, startCertDeployQueueCron,
} from "./routes/certificates.js";
import agentsRouter from "./routes/agents.js";
import usersRouter from "./routes/users.js";

const app = express();
const PORT = Number(process.env.PORT || 8080);
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

app.disable("x-powered-by");
app.set("trust proxy", String(process.env.TRUST_PROXY || "false") === "true");
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: false }));

// En-têtes de sécurité. L'interface n'appelle aucun service externe, donc une
// CSP stricte tient sans casser quoi que ce soit — hors styles et scripts en
// ligne, que les pages utilisent.
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
  next();
});

// Journal minimal : méthode, chemin, code, durée. Jamais de corps de requête,
// qui contiendrait clés privées et jetons.
app.use((req, res, next) => {
  const t0 = Date.now();
  res.on("finish", () => {
    if (req.path === "/healthz") return;
    console.log(`${req.method} ${req.path} → ${res.statusCode} (${Date.now() - t0}ms)`);
  });
  next();
});

// La version vient du paquet : la coder en dur dans l'interface la ferait
// diverger dès la première publication.
const VERSION = JSON.parse(
  fs.readFileSync(path.join(ROOT, "package.json"), "utf8")
).version;

app.get("/healthz", (_req, res) => res.json({ ok: true, version: VERSION }));

app.post("/api/login", loginHandler);
app.post("/api/logout", logoutHandler);

// Utilisateur courant : accessible à tout compte connecté, quel que soit le rôle.
app.get("/api/me", requireAuth, meHandler);
app.post("/api/me/password", requireAuth, changeOwnPasswordHandler);

// Les agents s'authentifient eux-mêmes (agent_id + token) : ce routeur est monté
// AVANT requireAuth. Ses routes d'administration portent leur propre garde.
app.use("/api/agents", agentsRouter);

// Administration des comptes : réservée aux administrateurs par le routeur lui-même.
app.use("/api/users", requireAuth, usersRouter);

// Certificats : lecture ouverte à tout compte, écriture filtrée route par route
// à l'intérieur du routeur.
app.use("/api/certificates", requireAuth, certificatesRouter);

app.use(express.static(path.join(ROOT, "public"), { extensions: ["html"] }));
app.get("/", (_req, res) => res.sendFile(path.join(ROOT, "public", "index.html")));

app.use((err, _req, res, _next) => {
  console.error("[erreur]", err.message);
  res.status(500).json({ error: err.message });
});

async function main() {
  await initSchema();
  await ensureCertSchema();
  await ensureBootstrapAdmin();

  const monitorMin = Number(process.env.MONITOR_INTERVAL_MIN || 360);
  const renewMin = Number(process.env.RENEW_INTERVAL_MIN || 720);
  try { startCertMonitorCron(monitorMin); } catch (e) { console.warn("[cron] sonde :", e.message); }
  try { startCertRenewCron(renewMin); } catch (e) { console.warn("[cron] renouvellement :", e.message); }
  try { startCertDeployQueueCron(30); } catch (e) { console.warn("[cron] file de deploiement :", e.message); }

  // Purge des sessions expirées, au démarrage puis toutes les heures.
  purgeExpiredSessions().catch(() => {});
  setInterval(() => purgeExpiredSessions().catch(() => {}), 3600_000).unref();

  app.listen(PORT, () => {
    console.log(`certfleet écoute sur http://0.0.0.0:${PORT}`);
    console.log(`sonde TLS toutes les ${monitorMin} min · renouvellement vérifié toutes les ${renewMin} min`);
  });
}

main().catch((e) => { console.error("[démarrage]", e); process.exit(1); });
