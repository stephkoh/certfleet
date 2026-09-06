// ═══════════════════════════════════════════════════════════════════
// routes/users.js — administration des comptes et de l'annuaire
//
// Tout ce routeur est réservé aux administrateurs, sauf les sessions de
// l'utilisateur courant. Chaque écriture est journalisée dans audit_log.
// ═══════════════════════════════════════════════════════════════════
import express from "express";
import { query } from "../db.js";
import {
  requireAdmin, hashPassword, passwordProblem, audit, ROLE_RANK,
} from "../auth.js";
import {
  getLdapConfig, saveLdapConfig, ldapSearchUsers, ldapSearchGroups, ldapTest,
} from "../lib/ldap.js";

const router = express.Router();

const ROLES = Object.keys(ROLE_RANK);
const PUBLIC_COLS = `id, username, email, display_name, role, source, is_active,
                     must_change_password, ldap_dn, last_login, created_at, updated_at`;

// ── Comptes ──────────────────────────────────────────────────────────
router.get("/", requireAdmin, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    const params = [];
    let where = "";
    if (q) {
      params.push(`%${q}%`);
      where = `WHERE username ILIKE $1 OR display_name ILIKE $1 OR email ILIKE $1`;
    }
    const r = await query(
      `SELECT ${PUBLIC_COLS},
              (SELECT count(*)::int FROM sessions s
                WHERE s.user_id = users.id AND s.expires_at > now()) AS active_sessions
         FROM users ${where}
        ORDER BY (role = 'admin') DESC, lower(username)`,
      params
    );
    res.json({ users: r.rows, roles: ROLES });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post("/", requireAdmin, async (req, res) => {
  try {
    const b = req.body || {};
    const username = String(b.username || "").trim();
    const source = b.source === "ldap" ? "ldap" : "local";
    const role = ROLES.includes(b.role) ? b.role : "viewer";

    if (!/^[A-Za-z0-9._\-@]{2,64}$/.test(username)) {
      return res.status(400).json({
        error: "Identifiant invalide : 2 à 64 caractères, lettres, chiffres, . _ - @",
      });
    }

    let hash = null;
    if (source === "local") {
      const problem = passwordProblem(b.password);
      if (problem) return res.status(400).json({ error: problem });
      hash = hashPassword(b.password);
    }

    const r = await query(
      `INSERT INTO users (username, email, display_name, role, source, password_hash,
                          ldap_dn, must_change_password)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING ${PUBLIC_COLS}`,
      [username, b.email || null, b.display_name || username, role, source, hash,
       b.ldap_dn || null, source === "local" ? b.must_change_password !== false : false]
    );
    await audit(req, "user.create", { target: username, detail: { role, source } });
    res.status(201).json(r.rows[0]);
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Cet identifiant existe déjà." });
    res.status(500).json({ error: e.message });
  }
});

router.put("/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const b = req.body || {};

    const cur = await query("SELECT id, username, role, is_active FROM users WHERE id = $1", [id]);
    if (!cur.rows.length) return res.status(404).json({ error: "Compte introuvable" });
    const before = cur.rows[0];

    // Garde-fou : on ne se retire pas soi-même le dernier accès administrateur.
    // Sans cela, une base sans admin actif ne serait plus administrable que via
    // ADMIN_TOKEN — et pas du tout si celui-ci n'est pas configuré.
    const losesAdmin = (b.role && b.role !== "admin" && before.role === "admin") ||
                       (b.is_active === false && before.role === "admin");
    if (losesAdmin) {
      const others = await query(
        "SELECT count(*)::int AS n FROM users WHERE role = 'admin' AND is_active AND id <> $1", [id]
      );
      if (others.rows[0].n === 0) {
        return res.status(409).json({
          error: "C'est le dernier administrateur actif : nommez-en un autre d'abord.",
        });
      }
    }

    const sets = [];
    const vals = [id];
    const put = (col, v) => { vals.push(v); sets.push(`${col} = $${vals.length}`); };

    if (b.email !== undefined) put("email", b.email || null);
    if (b.display_name !== undefined) put("display_name", b.display_name || null);
    if (b.ldap_dn !== undefined) put("ldap_dn", b.ldap_dn || null);
    if (b.role !== undefined) {
      if (!ROLES.includes(b.role)) return res.status(400).json({ error: "Rôle inconnu" });
      put("role", b.role);
    }
    if (b.is_active !== undefined) put("is_active", !!b.is_active);
    if (b.must_change_password !== undefined) put("must_change_password", !!b.must_change_password);

    if (!sets.length) return res.status(400).json({ error: "Rien à modifier" });
    sets.push("updated_at = now()");

    const r = await query(
      `UPDATE users SET ${sets.join(", ")} WHERE id = $1 RETURNING ${PUBLIC_COLS}`, vals
    );
    // Un compte désactivé doit perdre ses sessions immédiatement, sinon il
    // resterait connecté jusqu'à expiration.
    if (b.is_active === false) await query("DELETE FROM sessions WHERE user_id = $1", [id]);

    await audit(req, "user.update", { target: before.username, detail: b });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Réinitialisation par un administrateur. Le mot de passe fourni doit être
// changé à la première connexion.
router.post("/:id/password", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const cur = await query("SELECT username, source FROM users WHERE id = $1", [id]);
    if (!cur.rows.length) return res.status(404).json({ error: "Compte introuvable" });
    if (cur.rows[0].source !== "local") {
      return res.status(400).json({ error: "Compte d'annuaire : le mot de passe s'y change." });
    }
    const problem = passwordProblem(req.body?.password);
    if (problem) return res.status(400).json({ error: problem });

    await query(
      `UPDATE users SET password_hash = $2, must_change_password = true, updated_at = now()
        WHERE id = $1`,
      [id, hashPassword(req.body.password)]
    );
    await query("DELETE FROM sessions WHERE user_id = $1", [id]);
    await audit(req, "user.password_reset", { target: cur.rows[0].username });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete("/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const cur = await query("SELECT username, role FROM users WHERE id = $1", [id]);
    if (!cur.rows.length) return res.status(404).json({ error: "Compte introuvable" });

    if (cur.rows[0].role === "admin") {
      const others = await query(
        "SELECT count(*)::int AS n FROM users WHERE role = 'admin' AND is_active AND id <> $1", [id]
      );
      if (others.rows[0].n === 0) {
        return res.status(409).json({ error: "C'est le dernier administrateur actif." });
      }
    }
    if (req.user.id === id) {
      return res.status(409).json({ error: "On ne supprime pas son propre compte." });
    }

    await query("DELETE FROM users WHERE id = $1", [id]);   // sessions en cascade
    await audit(req, "user.delete", { target: cur.rows[0].username });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Révoque toutes les sessions d'un compte sans le désactiver.
router.post("/:id/revoke-sessions", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const r = await query("DELETE FROM sessions WHERE user_id = $1", [id]);
    await audit(req, "user.revoke_sessions", { target: String(id), detail: { count: r.rowCount } });
    res.json({ ok: true, revoked: r.rowCount });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Annuaire ─────────────────────────────────────────────────────────
router.get("/ldap/config", requireAdmin, async (_req, res) => {
  try { res.json(await getLdapConfig()); }             // sans le mot de passe
  catch (e) { res.status(500).json({ error: e.message }); }
});

router.put("/ldap/config", requireAdmin, async (req, res) => {
  try {
    const b = req.body || {};
    if (b.default_role && !ROLES.includes(b.default_role)) {
      return res.status(400).json({ error: "Rôle par défaut inconnu" });
    }
    if (b.group_roles !== undefined) {
      if (!Array.isArray(b.group_roles)) {
        return res.status(400).json({ error: "group_roles doit être une liste" });
      }
      for (const m of b.group_roles) {
        if (!m?.group || !ROLES.includes(m?.role)) {
          return res.status(400).json({ error: "Correspondance de groupe invalide" });
        }
      }
    }
    const cfg = await saveLdapConfig(b);
    // Le mot de passe de bind ne doit jamais partir dans le journal.
    const { bind_password, ...loggable } = b;
    await audit(req, "ldap.config", { detail: loggable });
    res.json(cfg);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post("/ldap/test", requireAdmin, async (req, res) => {
  try {
    const r = await ldapTest();
    await audit(req, "ldap.test", { ok: r.ok, detail: { error: r.error || null } });
    res.json(r);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get("/ldap/search", requireAdmin, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (q.length < 2) return res.json({ users: [] });
    res.json({ users: await ldapSearchUsers(q, { limit: 25 }) });
  } catch (e) { res.status(502).json({ error: `Annuaire : ${e.message}` }); }
});

router.get("/ldap/groups", requireAdmin, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (q.length < 2) return res.json({ groups: [] });
    res.json({ groups: await ldapSearchGroups(q, { limit: 25 }) });
  } catch (e) { res.status(502).json({ error: `Annuaire : ${e.message}` }); }
});

// Import d'un compte trouvé dans l'annuaire, sans attendre sa première connexion.
router.post("/ldap/import", requireAdmin, async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.username || !b.dn) return res.status(400).json({ error: "username et dn requis" });
    const role = ROLES.includes(b.role) ? b.role : "viewer";

    const r = await query(
      `INSERT INTO users (username, email, display_name, role, source, ldap_dn)
       VALUES ($1, $2, $3, $4, 'ldap', $5)
       ON CONFLICT (lower(username)) DO UPDATE
         SET email = EXCLUDED.email, display_name = EXCLUDED.display_name,
             ldap_dn = EXCLUDED.ldap_dn, role = EXCLUDED.role,
             source = 'ldap', is_active = true, updated_at = now()
       RETURNING ${PUBLIC_COLS}`,
      [b.username, b.email || null, b.display_name || b.username, role, b.dn]
    );
    await audit(req, "user.ldap_import", { target: b.username, detail: { role } });
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Journal d'audit ──────────────────────────────────────────────────
router.get("/audit", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 200, 1000);
    const params = [limit];
    const where = [];
    if (req.query.action) { params.push(String(req.query.action)); where.push(`action = $${params.length}`); }
    if (req.query.username) { params.push(String(req.query.username)); where.push(`username = $${params.length}`); }

    const r = await query(
      `SELECT id, ts, username, action, target, detail, ip, ok
         FROM audit_log ${where.length ? "WHERE " + where.join(" AND ") : ""}
        ORDER BY ts DESC LIMIT $1`,
      params
    );
    res.json({ entries: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

export default router;
