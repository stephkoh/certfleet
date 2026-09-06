// ════════════════════════════════════════════════════════════════════
// lib/certvault.js — Coffre : chiffrement au repos (AES-256-GCM).
// Sert à stocker les CLÉS PRIVÉES TLS et le token Gandi sans jamais les
// écrire en clair en base ni dans git.
// Clé de chiffrement HORS base : variable d'env CERT_VAULT_KEY
//   (64 hex = 32 octets, ou base64 32 octets, ou passphrase → SHA-256).
// Repli si absente : une clé est générée et stockée en base
//   (settings.cert_vault) + AVERTISSEMENT — à déplacer vers une
//   vraie variable d'env / Secret K8s pour un chiffrement réellement hors-DB.
// ════════════════════════════════════════════════════════════════════
import crypto from "node:crypto";
import { query } from "../db.js";

let _key = null;

function _parseKey(s) {
  if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, "hex");
  const b = Buffer.from(s, "base64");
  if (b.length === 32) return b;
  return crypto.createHash("sha256").update(s).digest(); // passphrase → 32 octets
}

async function getKey() {
  if (_key) return _key;
  const env = process.env.CERT_VAULT_KEY;
  if (env) { _key = _parseKey(env); return _key; }
  // Repli : clé persistée en base (moins bien que hors-DB, mais fonctionnel)
  const r = await query("SELECT value FROM settings WHERE key='cert_vault'").catch(() => ({ rows: [] }));
  let k = r.rows?.[0]?.value?.key;
  if (!k) {
    k = crypto.randomBytes(32).toString("base64");
    await query(
      `INSERT INTO settings(key, value, updated_at) VALUES('cert_vault', $1::jsonb, NOW())
       ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()`,
      [JSON.stringify({ key: k, generated_at: new Date().toISOString() })]
    );
    console.warn("[certvault] ⚠️ CERT_VAULT_KEY absente → clé générée et stockée en base (settings.cert_vault). Pour un vrai chiffrement HORS base, définir CERT_VAULT_KEY (env / Secret K8s) puis re-chiffrer.");
  }
  _key = Buffer.from(k, "base64");
  return _key;
}

// Renvoie true si la clé vient bien d'une source HORS base (env).
export function vaultKeyIsExternal() { return !!process.env.CERT_VAULT_KEY; }

// Chiffre une chaîne → "v1.<iv>.<tag>.<ciphertext>" (base64 chacun).
export async function vaultEncrypt(plaintext) {
  if (plaintext == null) return null;
  const key = await getKey();
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(String(plaintext), "utf8"), c.final()]);
  const tag = c.getAuthTag();
  return "v1." + iv.toString("base64") + "." + tag.toString("base64") + "." + ct.toString("base64");
}

// Déchiffre un blob "v1.iv.tag.ct".
export async function vaultDecrypt(blob) {
  if (blob == null) return null;
  const parts = String(blob).split(".");
  if (parts.length !== 4 || parts[0] !== "v1") throw new Error("format vault inconnu");
  const key = await getKey();
  const iv = Buffer.from(parts[1], "base64");
  const tag = Buffer.from(parts[2], "base64");
  const ct = Buffer.from(parts[3], "base64");
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}
