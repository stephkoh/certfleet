-- ════════════════════════════════════════════════════════════════════
-- Schéma de base — réglages et agents.
-- Les tables cert_* sont créées par ensureCertSchema() au démarrage.
-- Idempotent : rejouable sans risque.
-- ════════════════════════════════════════════════════════════════════

-- Réglages applicatifs (jeton d'enrôlement, identifiants DNS, statut des types…).
-- Les secrets y sont stockés CHIFFRÉS par lib/vault.js, jamais en clair.
CREATE TABLE IF NOT EXISTS settings (
  key         TEXT PRIMARY KEY,
  value       JSONB NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Agents installés sur les serveurs cibles.
-- Le hub ne détient AUCUN identifiant sur les cibles : c'est l'agent qui
-- interroge le hub (modèle « pull »), et lui seul peut déchiffrer la clé privée
-- grâce à sa paire de clés RSA générée localement à l'enrôlement.
CREATE TABLE IF NOT EXISTS agents (
  agent_id      TEXT PRIMARY KEY,
  token         TEXT NOT NULL,
  hostname      TEXT,
  fqdn          TEXT,
  ip            TEXT,
  os            TEXT,
  os_version    TEXT,
  kernel        TEXT,
  arch          TEXT,
  agent_version TEXT,
  pubkey        TEXT,               -- clé publique RSA, sert à chiffrer la clé privée du certificat
  sudo_mode     TEXT,
  last_seen     TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agents_last_seen_idx ON agents (last_seen DESC);

-- File de commandes consommée par les agents.
-- status : pending → approved → running → done | failed
CREATE TABLE IF NOT EXISTS commands (
  id          BIGSERIAL PRIMARY KEY,
  agent_id    TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  action      TEXT NOT NULL,
  kind        TEXT NOT NULL,
  payload     JSONB,
  status      TEXT NOT NULL DEFAULT 'pending',
  result      TEXT,
  exit_code   INTEGER,
  proposed_by TEXT,
  approved_by TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS commands_agent_status_idx ON commands (agent_id, status);
CREATE INDEX IF NOT EXISTS commands_created_idx ON commands (created_at DESC);

-- ════════════════════════════════════════════════════════════════════
-- Comptes, sessions et journal d'audit
-- ════════════════════════════════════════════════════════════════════

-- Comptes utilisateurs.
--   source = 'local' → mot de passe vérifié ici (scrypt, sel par compte)
--   source = 'ldap'  → mot de passe vérifié par bind sur l'annuaire, jamais stocké
--   role   = 'admin' | 'operator' | 'viewer'
CREATE TABLE IF NOT EXISTS users (
  id            BIGSERIAL PRIMARY KEY,
  username      TEXT NOT NULL,
  email         TEXT,
  display_name  TEXT,
  role          TEXT NOT NULL DEFAULT 'viewer',
  source        TEXT NOT NULL DEFAULT 'local',
  password_hash TEXT,               -- NULL pour les comptes LDAP
  ldap_dn       TEXT,               -- DN de bind, résolu à l'enrôlement ou à la connexion
  is_active     BOOLEAN NOT NULL DEFAULT true,
  must_change_password BOOLEAN NOT NULL DEFAULT false,
  last_login    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT users_role_chk   CHECK (role   IN ('admin','operator','viewer')),
  CONSTRAINT users_source_chk CHECK (source IN ('local','ldap'))
);
-- Identifiant unique sans distinction de casse : « Dupont » et « dupont » sont
-- le même compte, sinon un doublon LDAP créerait deux comptes aux droits différents.
CREATE UNIQUE INDEX IF NOT EXISTS users_username_uidx ON users (lower(username));

-- Sessions serveur. Seul le HACHÉ du jeton est conservé : une fuite de la base
-- ne permet pas de rejouer une session.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip          TEXT,
  user_agent  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx    ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at);

-- Journal d'audit : qui a fait quoi. Conservé même si le compte est supprimé,
-- d'où l'absence de clé étrangère et la copie du nom d'utilisateur.
CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGSERIAL PRIMARY KEY,
  ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
  username    TEXT,
  action      TEXT NOT NULL,
  target      TEXT,
  detail      JSONB,
  ip          TEXT,
  ok          BOOLEAN NOT NULL DEFAULT true
);
CREATE INDEX IF NOT EXISTS audit_ts_idx     ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS audit_action_idx ON audit_log (action, ts DESC);
