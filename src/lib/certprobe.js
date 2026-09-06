// ════════════════════════════════════════════════════════════════════
// lib/certprobe.js — Sonde TLS externe.
// Rouvre une VRAIE connexion TLS sur la cible et lit le certificat feuille
// réellement servi (≠ lire la base). C'est la boucle de vérification qui
// distingue certfleet d'un simple cron : un déploiement n'est « réussi » que
// si un client TLS externe voit le bon certificat (leçon du bug reflector).
// Aucune dépendance externe : module `tls` natif de Node.
// ════════════════════════════════════════════════════════════════════
import tls from "node:tls";
import net from "node:net";
import crypto from "node:crypto";

// Ports à TLS implicite (connexion chiffrée d'emblée). Le STARTTLS (587/143/110/389)
// sera ajouté plus tard ; ici on gère le direct-TLS qui couvre 95 % des cibles.
export const TLS_KINDS = {
  https:  { port: 443,  label: "HTTPS" },
  https8443: { port: 8443, label: "HTTPS 8443" },
  imaps:  { port: 993,  label: "IMAPS" },
  pop3s:  { port: 995,  label: "POP3S" },
  ldaps:  { port: 636,  label: "LDAPS" },
  smtps:  { port: 465,  label: "SMTPS" },
  ftps:   { port: 990,  label: "FTPS (implicite)" },
};

function _fingerprint256(der) {
  if (!der) return null;
  const hex = crypto.createHash("sha256").update(der).digest("hex").toUpperCase();
  return hex.match(/../g).join(":");
}

// Sonde une cible : renvoie le certificat feuille servi (ou une erreur).
export function probeTls({ host, port = 443, sni = null, timeout = 8000 } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    let done = false;
    let socket = null;
    const finish = (r) => {
      if (done) return; done = true;
      try { if (socket) socket.destroy(); } catch {}
      resolve({ ...r, host, port: Number(port) || 443, elapsed_ms: Date.now() - started });
    };
    if (!host) return finish({ ok: false, error: "hôte manquant" });

    try {
      socket = tls.connect({
        host,
        port: Number(port) || 443,
        servername: sni || (net.isIP(host) ? undefined : host), // pas de SNI sur une IP nue
        rejectUnauthorized: false,   // on veut LIRE le cert même expiré / mismatch
        timeout,
        ALPNProtocols: ["http/1.1"],
      }, () => {
        try {
          const c = socket.getPeerCertificate(true);
          if (!c || !c.valid_to) return finish({ ok: false, error: "aucun certificat présenté" });
          const sans = String(c.subjectaltname || "")
            .split(",").map(s => s.trim().replace(/^DNS:/i, "")).filter(Boolean);
          finish({
            ok: true,
            subject_cn: c.subject?.CN || null,
            issuer_cn: c.issuer?.CN || null,
            issuer_o: c.issuer?.O || null,
            serial: c.serialNumber || null,
            not_before: c.valid_from ? new Date(c.valid_from).toISOString() : null,
            not_after: c.valid_to ? new Date(c.valid_to).toISOString() : null,
            fingerprint_sha256: _fingerprint256(c.raw),
            sans,
            authorized: !!socket.authorized,
            authorization_error: socket.authorizationError ? String(socket.authorizationError) : null,
            protocol: socket.getProtocol ? socket.getProtocol() : null,
          });
        } catch (e) { finish({ ok: false, error: e.message }); }
      });
      socket.on("error", (e) => finish({ ok: false, error: e.message }));
      socket.on("timeout", () => finish({ ok: false, error: "timeout de connexion" }));
    } catch (e) { finish({ ok: false, error: e.message }); }
  });
}

// Statut métier d'un certificat selon son échéance.
// warnDays : seuil d'alerte (par défaut 21 j — adapté à l'ère 47/100 j).
export function expiryStatus(notAfter, { warnDays = 21 } = {}) {
  if (!notAfter) return { status: "unknown", days_left: null };
  const days = Math.floor((new Date(notAfter).getTime() - Date.now()) / 86400000);
  let status = "ok";
  if (days < 0) status = "expired";
  else if (days <= 7) status = "critical";
  else if (days <= warnDays) status = "warning";
  return { status, days_left: days };
}
