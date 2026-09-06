// ═══════════════════════════════════════════════════════════════════
// auth.js — comptes, sessions et contrôle d'accès
//
// Trois façons de s'authentifier, dans cet ordre :
//   1. cookie de session, posé après une connexion réussie ;
//   2. en-tête Authorization: Bearer <jeton de session>, pour l'API ;
//   3. ADMIN_TOKEN, jeton de secours défini côté serveur — il ouvre un accès
//      administrateur sans passer par la base. Il sert à créer le premier
//      compte et à se dépanner si l'annuaire tombe. À conserver pour cela.
//
// Les mots de passe locaux sont dérivés en scrypt avec un sel par compte.
// Les mots de passe d'annuaire ne sont jamais stockés : ils sont vérifiés par
// bind. Les jetons de session ne sont stockés que hachés.
//
// Les routes des agents ne passent PAS par ici : elles s'authentifient avec le
// couple agent_id + token délivré à l'enrôlement (cf. routes/agents.js).
// ═══════════════════════════════════════════════════════════════════
import crypto from "node:crypto";
import { query } from "./db.js";
import {
  getLdapConfig, ldapResolveUser, ldapVerifyPassword, roleFromGroups, ROLE_RANK,
} from "./lib/ldap.js";

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const COOKIE = "certfleet_session";
const SESSION_HOURS = Number(process.env.SESSION_HOURS || 12);

if (!ADMIN_TOKEN) {
  console.warn("[auth] ⚠️  ADMIN_TOKEN absent : aucun accès de secours si le mot de passe");
  console.warn("[auth]     administrateur est perdu. Générez-le : openssl rand -hex 32");
}

export { ROLE_RANK };

// ── Mots de passe locaux ─────────────────────────────────────────────
// scrypt, paramètres par défaut de Node (N=16384, r=8, p=1). Format stocké :
// scrypt$<sel hex>$<clé hex>, ce qui laisse la place à un autre algorithme
// plus tard sans migration destructrice.
export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(String(password), salt, 64);
  return `scrypt$${salt.toString("hex")}$${key.toString("hex")}`;
}

export function verifyPassword(password, stored) {
  if (!stored || !password) return false;
  const [algo, saltHex, keyHex] = String(stored).split("$");
  if (algo !== "scrypt" || !saltHex || !keyHex) return false;
  try {
    const expected = Buffer.from(keyHex, "hex");
    const actual = crypto.scryptSync(String(password), Buffer.from(saltHex, "hex"), expected.length);
    return crypto.timingSafeEqual(actual, expected);
  } catch { return false; }
}

// Règle volontairement simple : la longueur d'abord, c'est ce qui compte le plus.
export function passwordProblem(pw) {
  const s = String(pw || "");
  if (s.length < 12) return "Le mot de passe doit faire au moins 12 caractères.";
  if (!/[a-z]/.test(s) || !/[A-Z]/.test(s) || !/[0-9]/.test(s)) {
    return "Le mot de passe doit mêler minuscules, majuscules et chiffres.";
  }
  return null;
}

// ── Comparaison à temps constant ─────────────────────────────────────
function safeEqual(a, b) {
  const ba = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// ── Sessions ─────────────────────────────────────────────────────────
const hashToken = (t) => crypto.createHash("sha256").update(String(t)).digest("hex");

function clientIp(req) {
  if (!req) return null;
  const fwd = String(req.headers?.["x-forwarded-for"] || "").split(",")[0].trim();
  return fwd || req.ip || req.socket?.remoteAddress || null;
}

async function createSession(userId, req) {
  const token = crypto.randomBytes(32).toString("base64url");
  await query(
    `INSERT INTO sessions (token_hash, user_id, ip, user_agent, expires_at)
     VALUES ($1, $2, $3, $4, now() + ($5 || ' hours')::interval)`,
    [hashToken(token), userId, clientIp(req),
     String(req.headers["user-agent"] || "").slice(0, 300), String(SESSION_HOURS)]
  );
  return token;
}

async function userFromSession(token) {
  const r = await query(
    `UPDATE sessions SET last_seen = now()
      WHERE token_hash = $1 AND expires_at > now()
      RETURNING user_id`,
    [hashToken(token)]
  );
  if (!r.rows.length) return null;

  const u = await query(
    `SELECT id, username, display_name, email, role, source, is_active, must_change_password
       FROM users WHERE id = $1`,
    [r.rows[0].user_id]
  );
  const user = u.rows[0];
  if (!user || !user.is_active) return null;
  return user;
}

export async function purgeExpiredSessions() {
  const r = await query("DELETE FROM sessions WHERE expires_at < now()").catch(() => ({ rowCount: 0 }));
  if (r.rowCount) console.log(`[auth] ${r.rowCount} session(s) expirée(s) purgée(s)`);
  return r.rowCount;
}

// ── Journal d'audit ──────────────────────────────────────────────────
// N'échoue jamais bruyamment : un problème d'écriture du journal ne doit pas
// empêcher l'action elle-même, mais il doit rester visible dans les logs.
export async function audit(req, action, { target = null, detail = null, ok = true } = {}) {
  try {
    await query(
      `INSERT INTO audit_log (username, action, target, detail, ip, ok)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6)`,
      [req?.user?.username || null, action, target,
       detail ? JSON.stringify(detail) : null, clientIp(req), ok]
    );
  } catch (e) {
    console.warn("[audit] écriture impossible :", e.message);
  }
}

// ── Extraction du jeton ──────────────────────────────────────────────
function tokenFromRequest(req) {
  const h = req.headers.authorization || "";
  if (h.startsWith("Bearer ")) return h.slice(7).trim();
  const cookie = req.headers.cookie || "";
  const m = new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]+)").exec(cookie);
  return m ? decodeURIComponent(m[1]) : "";
}

// ── Gardes ───────────────────────────────────────────────────────────
export async function requireAuth(req, res, next) {
  try {
    const token = tokenFromRequest(req);
    if (!token) return res.status(401).json({ error: "Non authentifié" });

    // Jeton de secours : accès administrateur sans compte en base.
    if (ADMIN_TOKEN && safeEqual(token, ADMIN_TOKEN)) {
      req.user = {
        id: null, username: "admin", display_name: "Administrateur (jeton de secours)",
        email: null, role: "admin", source: "token", is_admin: true,
      };
      return next();
    }

    const user = await userFromSession(token);
    if (!user) return res.status(401).json({ error: "Session expirée ou invalide" });

    req.user = { ...user, is_admin: user.role === "admin" };
    next();
  } catch (e) {
    console.error("[auth]", e.message);
    res.status(500).json({ error: "Erreur d'authentification" });
  }
}

// requireRole("operator") laisse passer operator ET admin : les rôles sont
// hiérarchiques, pas des ensembles disjoints.
export function requireRole(minimum) {
  const floor = ROLE_RANK[minimum];
  if (!floor) throw new Error(`Rôle inconnu : ${minimum}`);
  return (req, res, next) => {
    const mine = ROLE_RANK[req.user?.role] || 0;
    if (mine < floor) {
      return res.status(403).json({
        error: `Action réservée au rôle « ${minimum} » ou supérieur.`,
        required: minimum, current: req.user?.role || null,
      });
    }
    next();
  };
}

export const requireAdmin = requireRole("admin");

// ── Amorçage : premier compte administrateur ─────────────────────────
// Sans compte, l'application serait inaccessible dès qu'ADMIN_TOKEN est absent.
// Le mot de passe généré n'est affiché qu'une fois, au démarrage.
export async function ensureBootstrapAdmin() {
  const r = await query("SELECT count(*)::int AS n FROM users WHERE role = 'admin' AND is_active");
  if (r.rows[0].n > 0) return null;

  const username = process.env.BOOTSTRAP_ADMIN || "admin";
  const password = process.env.BOOTSTRAP_PASSWORD || crypto.randomBytes(9).toString("base64url");
  const generated = !process.env.BOOTSTRAP_PASSWORD;

  await query(
    `INSERT INTO users (username, display_name, role, source, password_hash, must_change_password)
     VALUES ($1, $2, 'admin', 'local', $3, $4)
     ON CONFLICT (lower(username)) DO UPDATE
       SET role = 'admin', is_active = true, password_hash = EXCLUDED.password_hash`,
    [username, "Administrateur", hashPassword(password), generated]
  );

  console.log("┌───────────────────────────────────────────────────────────");
  console.log("│ Aucun administrateur en base : compte initial créé.");
  console.log(`│   identifiant  : ${username}`);
  console.log(`│   mot de passe : ${password}`);
  if (generated) console.log("│ À changer à la première connexion — non réaffiché.");
  console.log("└───────────────────────────────────────────────────────────");
  return { username, password };
}

// ── Connexion ────────────────────────────────────────────────────────
// Ordre : compte local d'abord, annuaire ensuite. Un compte local homonyme d'un
// compte d'annuaire ne doit pas pouvoir être contourné par ce dernier.
export async function loginHandler(req, res) {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");
  const legacyToken = String(req.body?.token || "");   // ancienne interface

  const fail = async (reason) => {
    await audit(req, "login", { target: username || "(jeton)", ok: false, detail: { reason } });
    // Message unique : ne pas révéler quels identifiants existent.
    return res.status(401).json({ error: "Identifiant ou mot de passe incorrect." });
  };

  try {
    if (legacyToken && !username) {
      if (ADMIN_TOKEN && safeEqual(legacyToken, ADMIN_TOKEN)) {
        setSessionCookie(res, legacyToken);
        return res.json({ ok: true, user: { username: "admin", role: "admin", source: "token" } });
      }
      return fail("jeton de secours invalide");
    }

    if (!username || !password) {
      return res.status(400).json({ error: "Identifiant et mot de passe requis." });
    }

    const found = await query(
      `SELECT id, username, display_name, email, role, source, password_hash, ldap_dn,
              is_active, must_change_password
         FROM users WHERE lower(username) = lower($1)`,
      [username]
    );
    const local = found.rows[0] || null;
    if (local && !local.is_active) return fail("compte désactivé");

    let user = null;

    if (local && local.source === "local") {
      if (!verifyPassword(password, local.password_hash)) return fail("mot de passe local invalide");
      user = local;
    } else {
      // Compte d'annuaire déjà connu, ou inconnu si l'auto-création est active.
      const cfg = await getLdapConfig();
      if (!cfg.enabled) return fail("compte inconnu et annuaire désactivé");

      const dir = await ldapResolveUser(username).catch((e) => {
        console.warn("[auth] annuaire injoignable :", e.message);
        return null;
      });
      if (!dir) return fail("compte introuvable dans l'annuaire");
      if (dir.disabled) return fail("compte désactivé dans l'annuaire");
      if (!(await ldapVerifyPassword(dir.dn, password))) return fail("bind refusé");

      if (local) {
        // Compte déjà connu : on rafraîchit ce qui vient de l'annuaire. Le rôle
        // n'est réécrit que si une correspondance de groupe existe, pour ne pas
        // écraser un rôle attribué à la main dans l'interface.
        const mapped = cfg.group_roles?.length
          ? roleFromGroups(dir.groups, cfg.group_roles, null)
          : null;
        const upd = await query(
          `UPDATE users SET display_name = $2, email = $3, ldap_dn = $4,
                            role = COALESCE($5, role), updated_at = now()
            WHERE id = $1 RETURNING *`,
          [local.id, dir.display_name, dir.email, dir.dn, mapped]
        );
        user = upd.rows[0];
      } else {
        if (!cfg.auto_create) return fail("auto-création désactivée");
        const role = roleFromGroups(dir.groups, cfg.group_roles, cfg.default_role);
        const ins = await query(
          `INSERT INTO users (username, display_name, email, role, source, ldap_dn)
           VALUES ($1, $2, $3, $4, 'ldap', $5) RETURNING *`,
          [dir.username || username, dir.display_name, dir.email, role, dir.dn]
        );
        user = ins.rows[0];
        console.log(`[auth] compte d'annuaire créé : ${user.username} (rôle ${user.role})`);
      }
    }

    const token = await createSession(user.id, req);
    await query("UPDATE users SET last_login = now() WHERE id = $1", [user.id]);
    setSessionCookie(res, token);

    req.user = user;
    await audit(req, "login", { target: user.username, detail: { source: user.source } });

    res.json({
      ok: true, token,
      user: {
        id: user.id, username: user.username, display_name: user.display_name,
        email: user.email, role: user.role, source: user.source,
        must_change_password: user.must_change_password,
      },
    });
  } catch (e) {
    console.error("[auth] connexion :", e);
    res.status(500).json({ error: "Erreur interne à la connexion" });
  }
}

function setSessionCookie(res, token) {
  const secure = String(process.env.COOKIE_SECURE || "true") !== "false";
  res.setHeader("Set-Cookie",
    `${COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; ` +
    `Max-Age=${SESSION_HOURS * 3600}` + (secure ? "; Secure" : ""));
}

export async function logoutHandler(req, res) {
  const token = tokenFromRequest(req);
  if (token) {
    await query("DELETE FROM sessions WHERE token_hash = $1", [hashToken(token)]).catch(() => {});
  }
  res.setHeader("Set-Cookie", `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
  res.json({ ok: true });
}

// GET /api/me — l'interface s'en sert pour adapter l'affichage au rôle.
export function meHandler(req, res) {
  res.json({
    id: req.user.id, username: req.user.username, display_name: req.user.display_name,
    email: req.user.email, role: req.user.role, source: req.user.source,
    is_admin: req.user.role === "admin",
    must_change_password: !!req.user.must_change_password,
  });
}

// POST /api/me/password — changement de son propre mot de passe.
export async function changeOwnPasswordHandler(req, res) {
  try {
    if (req.user.source !== "local" || !req.user.id) {
      return res.status(400).json({
        error: "Ce compte est géré par l'annuaire : le mot de passe s'y change.",
      });
    }
    const current = String(req.body?.current || "");
    const next = String(req.body?.next || "");

    const r = await query("SELECT password_hash FROM users WHERE id = $1", [req.user.id]);
    if (!verifyPassword(current, r.rows[0]?.password_hash)) {
      await audit(req, "password.change", { ok: false, detail: { reason: "mot de passe actuel faux" } });
      return res.status(401).json({ error: "Mot de passe actuel incorrect." });
    }
    const problem = passwordProblem(next);
    if (problem) return res.status(400).json({ error: problem });
    if (next === current) return res.status(400).json({ error: "Le nouveau mot de passe doit être différent." });

    await query(
      `UPDATE users SET password_hash = $2, must_change_password = false, updated_at = now()
        WHERE id = $1`,
      [req.user.id, hashPassword(next)]
    );
    // Les autres sessions tombent : un changement de mot de passe doit évincer
    // une session éventuellement volée.
    const keep = hashToken(tokenFromRequest(req));
    await query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2", [req.user.id, keep]);

    await audit(req, "password.change", { target: req.user.username });
    res.json({ ok: true });
  } catch (e) {
    console.error("[auth] changement de mot de passe :", e.message);
    res.status(500).json({ error: e.message });
  }
}
