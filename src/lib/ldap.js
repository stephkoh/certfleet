// ═══════════════════════════════════════════════════════════════════
// lib/ldap.js — annuaire Active Directory / OpenLDAP
//
// Deux usages seulement :
//   1. vérifier un mot de passe (simple bind sur le DN de l'utilisateur) ;
//   2. rechercher utilisateurs et groupes pour les rattacher à un rôle.
//
// certfleet n'écrit JAMAIS dans l'annuaire. Le compte de service n'a besoin
// que d'un droit de lecture.
//
// La configuration vit en base (table settings, clé « ldap ») pour être
// modifiable depuis l'interface ; les variables d'environnement servent de
// valeurs par défaut, pratiques pour un déploiement conteneurisé.
// ═══════════════════════════════════════════════════════════════════
import { Client } from "ldapts";
import { query } from "../db.js";
import { vaultEncrypt, vaultDecrypt } from "./vault.js";

const DEFAULTS = {
  enabled: false,
  url: "",                  // ldaps://dc01.exemple.local:636
  url_fallback: "",         // second contrôleur de domaine
  base_dn: "",              // DC=exemple,DC=local
  bind_dn: "",              // compte de service, lecture seule
  bind_password: "",        // chiffré en base
  user_filter: "(objectClass=person)",
  login_attrs: "sAMAccountName,uid,userPrincipalName,mail",
  group_base_dn: "",        // vide = base_dn
  tls_reject_unauthorized: true,
  tls_check_hostname: true,
  ca_cert_pem: "",
  default_role: "viewer",   // rôle des comptes AD sans correspondance de groupe
  auto_create: true,        // créer le compte à la première connexion réussie
  group_roles: [],          // [{ group, role }] — le rôle le plus fort gagne
};

function fromEnv() {
  const e = process.env;
  const b = (v, d) => (v == null || v === "" ? d : String(v).toLowerCase() !== "false");
  return {
    enabled: b(e.LDAP_ENABLED, !!e.LDAP_URL),
    url: e.LDAP_URL || "",
    url_fallback: e.LDAP_URL_FALLBACK || "",
    base_dn: e.LDAP_BASE_DN || "",
    bind_dn: e.LDAP_BIND_DN || "",
    bind_password: e.LDAP_BIND_PASSWORD || "",
    user_filter: e.LDAP_USER_FILTER || DEFAULTS.user_filter,
    login_attrs: e.LDAP_LOGIN_ATTRS || DEFAULTS.login_attrs,
    group_base_dn: e.LDAP_GROUP_BASE_DN || "",
    tls_reject_unauthorized: b(e.LDAP_TLS_REJECT_UNAUTHORIZED, true),
    tls_check_hostname: b(e.LDAP_TLS_CHECK_HOSTNAME, true),
    ca_cert_pem: e.LDAP_CA_CERT_PEM || "",
    default_role: e.LDAP_DEFAULT_ROLE || DEFAULTS.default_role,
    auto_create: b(e.LDAP_AUTO_CREATE, true),
    group_roles: [],
  };
}

// ── Configuration ────────────────────────────────────────────────────
// Le mot de passe du compte de service est chiffré au repos, comme les clés
// privées des certificats.
export async function getLdapConfig({ withSecret = false } = {}) {
  const r = await query("SELECT value FROM settings WHERE key='ldap'").catch(() => ({ rows: [] }));
  const stored = r.rows[0]?.value || {};
  const env = fromEnv();
  const cfg = { ...DEFAULTS, ...env, ...stored };

  if (stored.bind_password_enc) {
    cfg.bind_password = withSecret
      ? await vaultDecrypt(stored.bind_password_enc).catch(() => "")
      : "";
  }
  cfg.has_bind_password = !!(stored.bind_password_enc || env.bind_password);
  delete cfg.bind_password_enc;
  if (!withSecret) delete cfg.bind_password;
  return cfg;
}

export async function saveLdapConfig(patch) {
  const cur = await query("SELECT value FROM settings WHERE key='ldap'").catch(() => ({ rows: [] }));
  const next = { ...(cur.rows[0]?.value || {}) };

  for (const k of Object.keys(DEFAULTS)) {
    if (k === "bind_password") continue;
    if (patch[k] !== undefined) next[k] = patch[k];
  }
  // Le mot de passe n'est écrasé que s'il est réellement fourni : l'interface
  // renvoie une chaîne vide quand l'utilisateur n'y a pas touché.
  if (typeof patch.bind_password === "string" && patch.bind_password !== "") {
    next.bind_password_enc = await vaultEncrypt(patch.bind_password);
  }

  await query(
    `INSERT INTO settings(key, value, updated_at) VALUES('ldap', $1::jsonb, now())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
    [JSON.stringify(next)]
  );
  return getLdapConfig();
}

export async function ldapConfigured() {
  const c = await getLdapConfig({ withSecret: true });
  return !!(c.enabled && c.url && c.base_dn && c.bind_dn && c.bind_password);
}

// ── Client ───────────────────────────────────────────────────────────
function buildClient(cfg, attempt = 0) {
  const urls = [cfg.url, cfg.url_fallback].map(s => String(s || "").trim()).filter(Boolean);
  const url = urls.length ? urls[attempt % urls.length] : cfg.url;
  const opts = { url, timeout: 10000, connectTimeout: 10000 };

  if (url.toLowerCase().startsWith("ldaps://")) {
    const tls = {};
    if (cfg.tls_reject_unauthorized === false) tls.rejectUnauthorized = false;
    if (cfg.ca_cert_pem) tls.ca = [cfg.ca_cert_pem];
    // Un DNS de domaine en round-robin (exemple.local) ne correspond pas aux SAN
    // des certificats des contrôleurs (dc01.exemple.local). On peut alors ne
    // désactiver que le contrôle du nom : la chaîne reste vérifiée.
    if (cfg.tls_check_hostname === false) tls.checkServerIdentity = () => undefined;
    if (Object.keys(tls).length) opts.tlsOptions = tls;
  }
  return new Client(opts);
}

// Les contrôleurs de domaine ferment parfois la connexion (ECONNRESET) : on
// retente en basculant sur le second DC. Jamais sur une erreur d'identifiants.
const NET_ERR = /ECONNRESET|ETIMEDOUT|ECONNREFUSED|ENOTFOUND|socket hang up|EHOSTUNREACH/i;

async function withRetry(fn, attempts = 3) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try { return await fn(i); }
    catch (e) {
      last = e;
      if (!NET_ERR.test(String(e.message || e)) || i === attempts - 1) break;
      console.warn(`[ldap] tentative ${i + 1}/${attempts} : ${e.message}`);
      await new Promise(r => setTimeout(r, 200 * (i + 1)));
    }
  }
  throw last;
}

// Échappement RFC 4515. Sans lui, un identifiant contenant « ) » ou « * »
// réécrirait le filtre de recherche.
function esc(v) {
  return String(v || "")
    .replace(/\\/g, "\\5c").replace(/\*/g, "\\2a")
    .replace(/\(/g, "\\28").replace(/\)/g, "\\29").replace(/\0/g, "\\00");
}

const USER_ATTRS = ["dn", "sAMAccountName", "uid", "userPrincipalName", "mail",
                    "displayName", "cn", "givenName", "sn", "memberOf", "userAccountControl"];

function mapUser(e) {
  const memberOf = e.memberOf == null ? [] : (Array.isArray(e.memberOf) ? e.memberOf : [e.memberOf]);
  // Bit 2 de userAccountControl = ACCOUNTDISABLE.
  const uac = Number(e.userAccountControl || 0);
  return {
    dn: e.dn,
    username: e.sAMAccountName || e.uid || e.userPrincipalName || e.cn || "",
    display_name: e.displayName || e.cn ||
      [e.givenName, e.sn].filter(Boolean).join(" ") || e.sAMAccountName || "",
    email: e.mail || e.userPrincipalName || null,
    groups: memberOf.map(String),
    disabled: !!(uac & 2),
  };
}

// ── Recherche d'utilisateurs ─────────────────────────────────────────
// exact=false : jokers, pour la recherche depuis l'interface.
// exact=true  : égalité stricte, pour identifier UN compte à la connexion.
export async function ldapSearchUsers(q, { limit = 20, exact = false } = {}) {
  const cfg = await getLdapConfig({ withSecret: true });
  if (!cfg.enabled || !cfg.url || !cfg.bind_dn) return [];

  const attrs = String(cfg.login_attrs).split(",").map(s => s.trim()).filter(Boolean);
  const needle = exact ? esc(q) : `*${esc(q)}*`;
  const or = `(|${attrs.map(a => `(${a}=${needle})`).join("")})`;
  // Exclut les comptes machine AD, dont le sAMAccountName se termine par « $ ».
  const filter = `(&${cfg.user_filter}(!(sAMAccountName=*$))${or})`;

  return withRetry(async (attempt) => {
    const client = buildClient(cfg, attempt);
    try {
      await client.bind(cfg.bind_dn, cfg.bind_password);
      const { searchEntries } = await client.search(cfg.base_dn, {
        scope: "sub", filter, sizeLimit: limit, attributes: USER_ATTRS,
      });
      return searchEntries.map(mapUser);
    } finally { try { await client.unbind(); } catch {} }
  });
}

// Identifie UN compte à partir du login saisi. En cas d'ambiguïté on refuse
// plutôt que de deviner : deux comptes peuvent porter des droits différents.
export async function ldapResolveUser(login) {
  const found = await ldapSearchUsers(login, { limit: 3, exact: true });
  if (!found.length) return null;
  if (found.length === 1) return found[0];
  const exact = found.find(u => u.username.toLowerCase() === String(login).toLowerCase());
  return exact || null;
}

// ── Recherche de groupes ─────────────────────────────────────────────
export async function ldapSearchGroups(q, { limit = 20 } = {}) {
  const cfg = await getLdapConfig({ withSecret: true });
  if (!cfg.enabled || !cfg.url || !cfg.bind_dn) return [];

  const base = cfg.group_base_dn || cfg.base_dn;
  const filter = `(&(objectClass=group)(|(cn=*${esc(q)}*)(sAMAccountName=*${esc(q)}*)))`;

  return withRetry(async (attempt) => {
    const client = buildClient(cfg, attempt);
    try {
      await client.bind(cfg.bind_dn, cfg.bind_password);
      const { searchEntries } = await client.search(base, {
        scope: "sub", filter, sizeLimit: limit,
        attributes: ["dn", "cn", "description", "sAMAccountName"],
      });
      return searchEntries.map(e => ({
        dn: e.dn,
        name: e.cn || e.sAMAccountName || e.dn,
        description: e.description || null,
      }));
    } finally { try { await client.unbind(); } catch {} }
  });
}

// ── Vérification du mot de passe ─────────────────────────────────────
// Certains annuaires acceptent un bind avec mot de passe vide comme un bind
// anonyme : on refuse donc explicitement le mot de passe vide.
export async function ldapVerifyPassword(dn, password) {
  if (!dn || !password) return false;
  const cfg = await getLdapConfig({ withSecret: true });
  if (!cfg.enabled || !cfg.url) return false;

  for (let i = 0; i < 3; i++) {
    const client = buildClient(cfg, i);
    try {
      await client.bind(String(dn), String(password));
      try { await client.unbind(); } catch {}
      return true;
    } catch (e) {
      try { await client.unbind(); } catch {}
      const msg = String(e.message || e);
      const badCreds = e.code === 49 || /InvalidCredentials|data 5[0-9]{2}/i.test(msg);
      if (badCreds || !NET_ERR.test(msg) || i === 2) {
        if (!badCreds) console.warn(`[ldap] bind "${dn}" : ${msg}`);
        return false;
      }
      await new Promise(r => setTimeout(r, 200 * (i + 1)));
    }
  }
  return false;
}

// ── Rôle déduit de l'appartenance aux groupes ────────────────────────
// Le rôle le plus fort l'emporte : appartenir au groupe des lecteurs ne retire
// rien à un administrateur.
export const ROLE_RANK = { viewer: 1, operator: 2, admin: 3 };

export function roleFromGroups(groups, mapping, fallback = "viewer") {
  const mine = (groups || []).map(g => String(g).toLowerCase());
  let best = null;
  for (const m of mapping || []) {
    if (!m || !m.group || !ROLE_RANK[m.role]) continue;
    const want = String(m.group).toLowerCase();
    // Correspondance sur le DN complet ou sur le seul CN, pour ne pas imposer
    // la saisie d'un DN entier dans l'interface.
    const hit = mine.some(g => g === want || g.startsWith(`cn=${want},`));
    if (hit && (!best || ROLE_RANK[m.role] > ROLE_RANK[best])) best = m.role;
  }
  return best || fallback;
}

// ── Test de connectivité, pour le bouton « Tester » de l'interface ───
export async function ldapTest() {
  const cfg = await getLdapConfig({ withSecret: true });
  if (!cfg.url) return { ok: false, error: "Aucune URL d'annuaire configurée" };
  if (!cfg.bind_dn || !cfg.bind_password) return { ok: false, error: "Compte de service incomplet" };

  const t0 = Date.now();
  try {
    const n = await withRetry(async (attempt) => {
      const client = buildClient(cfg, attempt);
      try {
        await client.bind(cfg.bind_dn, cfg.bind_password);
        const { searchEntries } = await client.search(cfg.base_dn, {
          scope: "sub", filter: `(&${cfg.user_filter}(!(sAMAccountName=*$)))`,
          sizeLimit: 5, attributes: ["dn"],
        });
        return searchEntries.length;
      } finally { try { await client.unbind(); } catch {} }
    });
    const ms = Date.now() - t0;
    return { ok: true, ms, sample: n, message: `Connexion établie — ${n} compte(s) lus en ${ms} ms` };
  } catch (e) {
    return { ok: false, ms: Date.now() - t0, error: e.message };
  }
}
