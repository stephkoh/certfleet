// ═══════════════════════════════════════════════════════════════════
// db.js — accès PostgreSQL
// Volontairement minimal : un pool, une fonction query(). Pas de
// multi-schéma ni de contexte société (c'était propre à l'ERP d'origine).
// ═══════════════════════════════════════════════════════════════════
import pg from "pg";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const { Pool } = pg;
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("[db] DATABASE_URL absente — voir .env.example");
  process.exit(1);
}

export const pool = new Pool({
  connectionString: DATABASE_URL,
  max: Number(process.env.PGPOOL_MAX || 10),
});

pool.on("error", (e) => console.error("[db] erreur du pool :", e.message));

export async function query(sql, params = []) {
  return pool.query(sql, params);
}

export async function getClient() {
  return pool.connect();
}

// Crée le schéma au démarrage. Idempotent : on peut le rejouer sans risque.
// Les tables cert_* sont créées par ensureCertSchema() dans routes/certificates.js ;
// ici on pose ce qui est propre à l'application autonome (réglages + agents).
export async function initSchema() {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  const sql = fs.readFileSync(path.join(dir, "schema.sql"), "utf8");
  await pool.query(sql);
  console.log("[db] schéma vérifié");
}
