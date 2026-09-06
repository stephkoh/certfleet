// ════════════════════════════════════════════════════════════════════
// lib/gandi.js — API Gandi LiveDNS (challenge DNS-01 pour ACME).
// On ne fait QUE poser/retirer un TXT temporaire _acme-challenge — on ne
// touche à AUCUN enregistrement existant (A, MX, CNAME…) ni au domaine ni
// au certificat acheté. fetch natif, aucune dépendance.
// Auth : PAT Gandi → "Bearer <token>" ; clé API legacy → "Apikey <key>".
// ════════════════════════════════════════════════════════════════════

const GANDI_BASE = process.env.GANDI_LIVEDNS_BASE || "https://api.gandi.net/v5/livedns";

function _authHeader(token, scheme) {
  const s = (scheme || "bearer").toLowerCase();
  return s === "apikey" ? `Apikey ${token}` : `Bearer ${token}`;
}

async function _gandi(path, { token, scheme, method = "GET", body } = {}) {
  const r = await fetch(GANDI_BASE + path, {
    method,
    headers: {
      "Authorization": _authHeader(token, scheme),
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const txt = await r.text();
  let data = null; try { data = txt ? JSON.parse(txt) : null; } catch { data = txt; }
  if (!r.ok) {
    const msg = (data && (data.message || data.cause)) || (typeof data === "string" ? data : "") || ("HTTP " + r.status);
    const e = new Error("Gandi LiveDNS : " + msg); e.status = r.status; e.body = data; throw e;
  }
  return data;
}

// Vérifie le token + liste les domaines gérés (pour l'UI de config).
export async function gandiListDomains({ token, scheme } = {}) {
  const d = await _gandi("/domains", { token, scheme });
  return (Array.isArray(d) ? d : []).map(x => ({ fqdn: x.fqdn, domain: x.domain || x.fqdn }));
}

// Le domaine (zone apex) doit être géré chez Gandi. On le retrouve en
// remontant les labels du FQDN jusqu'à trouver une zone existante.
export async function gandiFindZone({ token, scheme, fqdn }) {
  const clean = String(fqdn || "").replace(/^\*\./, "").replace(/\.$/, "");
  const labels = clean.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const cand = labels.slice(i).join(".");
    try { await _gandi(`/domains/${encodeURIComponent(cand)}`, { token, scheme }); return cand; }
    catch (e) { if (e.status && e.status !== 404) throw e; }
  }
  throw new Error(`Zone DNS introuvable chez Gandi pour ${fqdn}`);
}

// Nom relatif du TXT _acme-challenge pour un identifiant ACME.
// ex : *.example.com (zone example.com) → "_acme-challenge"
//      app.example.net       (zone example.net)          → "_acme-challenge.app"
export function acmeChallengeName(identifier, zone) {
  const host = String(identifier || "").replace(/^\*\./, "").replace(/\.$/, "");
  if (host === zone) return "_acme-challenge";
  const sub = host.endsWith("." + zone) ? host.slice(0, -(zone.length + 1)) : host;
  return "_acme-challenge." + sub;
}

// Pose (upsert) le TXT. Plusieurs valeurs possibles si plusieurs identifiants
// partagent le même nom de challenge (ex. example.com + *.example.com).
export async function gandiUpsertTxt({ token, scheme, zone, name, values, ttl = 300 }) {
  const vals = (Array.isArray(values) ? values : [values]).map(v => `"${v}"`);
  await _gandi(`/domains/${encodeURIComponent(zone)}/records/${encodeURIComponent(name)}/TXT`, {
    token, scheme, method: "PUT", body: { rrset_ttl: ttl, rrset_values: vals },
  });
  return true;
}

// Retire le TXT temporaire.
export async function gandiDeleteTxt({ token, scheme, zone, name }) {
  try {
    await _gandi(`/domains/${encodeURIComponent(zone)}/records/${encodeURIComponent(name)}/TXT`, {
      token, scheme, method: "DELETE",
    });
  } catch (e) { if (e.status !== 404) throw e; }
  return true;
}
