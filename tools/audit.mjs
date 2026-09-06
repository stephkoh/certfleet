// Audit de cohérence : vocabulaire hérité, routes réellement exposées,
// promesses de la documentation face au code.
import fs from "node:fs";
import path from "node:path";

const files = [];
(function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    if (e.name === "node_modules" || e.name === ".git" || e.name.startsWith("_")) continue;
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (/\.(js|mjs|sh|ps1|html|sql|md|yml|yaml)$|Dockerfile|cert-install$/.test(e.name)) files.push(p);
  }
})(".");

const read = (f) => fs.readFileSync(f, "utf8");
const rel = (f) => f.replace(/\\/g, "/").replace(/^\.\//, "");

let issues = 0;
const section = (t) => console.log("\n" + t + "\n" + "─".repeat(t.length));
const bad = (f, line, msg) => { issues++; console.log(`  ✗ ${rel(f)}:${line}  ${msg}`); };
const ok = (msg) => console.log(`  ✓ ${msg}`);

function scan(patterns, label) {
  section(label);
  let found = 0;
  for (const f of files) {
    const lines = read(f).split("\n");
    lines.forEach((l, i) => {
      for (const { re, why } of patterns) {
        if (re.test(l)) { bad(f, i + 1, why + "  →  " + l.trim().slice(0, 110)); found++; }
      }
    });
  }
  if (!found) ok("rien à signaler");
}

// ── 1. Vocabulaire et chemins hérités de l'ERP d'origine ──
scan([
  { re: /IT\s*[›>»]\s*ADM|onglet ADM|module ADM|agent ADM/i, why: "renvoie à un écran de l'ERP d'origine" },
  { re: /\/api\/adm\//, why: "chemin d'API inexistant dans certfleet" },
  { re: /\blot\s*[123]\b|lots? suivants?/i, why: "découpage en lots propre au projet d'origine" },
  { re: /SUDO_SECURE|\bCVE\b|\bdnf\b/, why: "fonctionnalité retirée de l'agent" },
  { re: /brainity|acri[-_ ]?st|acrist/i, why: "référence interne" },
], "1. Vocabulaire et chemins hérités");

// ── 2. Chemins d'API cités hors du code serveur ──
section("2. Chemins d'API cités hors du serveur");
const routes = new Set();
for (const f of files.filter((x) => /src[\\/]routes[\\/]/.test(x))) {
  const mount = /agents\.js$/.test(f) ? "/api/agents"
              : /users\.js$/.test(f) ? "/api/users"
              : /certificates\.js$/.test(f) ? "/api/certificates" : "";
  for (const m of read(f).matchAll(/router\.(get|post|put|patch|delete)\("([^"]+)"/g)) {
    routes.add((mount + (m[2] === "/" ? "" : m[2])).replace(/\/:[^/]+/g, "/*"));
  }
}
for (const r of ["/api/login", "/api/logout", "/api/me", "/api/me/password", "/healthz"]) routes.add(r);

let refIssues = 0;
for (const f of files.filter((x) => /public[\\/]|agent[\\/]|\.md$/.test(x))) {
  const lines = read(f).split("\n");
  lines.forEach((l, i) => {
    for (const m of l.matchAll(/["'`\s(]\/api\/[a-z0-9/_.-]+/gi)) {
      const p = m[0].slice(1).split("?")[0].replace(/\/$/, "").replace(/\/\$\{[^}]*\}/g, "/*");
      if (/\$\{|\+/.test(p)) continue;
      const norm = p.replace(/\/[0-9]+$/, "/*");
      const hit = [...routes].some((r) => r === norm || r === norm + "/" || norm.startsWith(r.replace("/*", "")));
      if (!hit) { bad(f, i + 1, "route inconnue du serveur : " + p); refIssues++; }
    }
  });
}
if (!refIssues) ok("toutes les routes citées existent");

// ── 3. Types de cible : promesse contre réalité ──
section("3. Types de cible");
const certs = read("src/routes/certificates.js");
const types = [...certs.matchAll(/\{ type: "([a-z0-9_]+)",\s+label: "([^"]+)", mode: "([a-z0-9]+)"/g)]
  .map((m) => ({ type: m[1], label: m[2], mode: m[3] }));

const storeMatch = certs.match(/const STORE_TYPES = new Set\(\[([^\]]+)\]\)/);
const storeTypes = storeMatch ? [...storeMatch[1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]) : [];

const linuxAgent = read("agent/certfleet-agent.sh");
const winAgent = read("agent/certfleet-agent.ps1");

console.log(`  ${types.length} types déclarés\n`);
for (const t of types) {
  const fields = certs.slice(certs.indexOf(`{ type: "${t.type}",`)).split("] },")[0];
  // pem_path couvre les serveurs qui lisent le certificat et la clé dans un
  // seul fichier (HAProxy) : le hub s'en sert pour les deux chemins.
  const hasPaths = (/key: "cert_path"/.test(fields) && /key: "key_path"/.test(fields))
                || /key: "pem_path"/.test(fields);
  const isStore = storeTypes.includes(t.type);

  let verdict, detail;
  if (t.mode === "k8s") { verdict = "surveillance seule"; detail = "cert-manager reste maître"; }
  else if (t.mode === "api") { verdict = "connecteur direct"; detail = "le hub appelle l'appliance"; }
  else if (isStore) {
    // Un type « magasin » doit être traité par au moins un des deux agents.
    const inWin = new RegExp(`"${t.type}"`).test(winAgent);
    const inLinux = new RegExp(t.type).test(linuxAgent);
    const handled = inWin || inLinux;
    verdict = !handled ? "MODE MAGASIN NON TRAITÉ"
            : inWin && inLinux ? "agents Linux + Windows"
            : inWin ? "agent Windows" : "agent Linux";
    detail = !handled ? "aucun agent ne sait le poser"
           : inWin ? "magasin + liaison de service" : "keytool + redémarrage";
    if (!handled) issues++;
  }
  else if (hasPaths) { verdict = "agent, mode fichier"; detail = "cert_path + key_path"; }
  else { verdict = "PARAMÈTRES MANQUANTS"; detail = "ni chemins ni mode magasin"; issues++; }

  const flag = /NON TRAITÉ|MANQUANTS/.test(verdict) ? "✗" : "✓";
  console.log(`  ${flag} ${t.type.padEnd(15)} ${verdict.padEnd(24)} ${detail}`);
}

// ── 4. L'agent et le hub parlent-ils le même langage ? ──
section("4. Cohérence agent ↔ hub");
const payloadKeys = [...certs.matchAll(/^\s{4}([a-z_]+):/gm)].map((m) => m[1]);
const sent = new Set(["target_type", "mode", "cert_pem", "cert_path", "key_path", "chain_path",
                      "chain_pem", "key_iv", "aeskey_enc", "key_cipher", "reload_cmd",
                      "common_name", "params"]);
for (const k of sent) {
  const inLinux = linuxAgent.includes(k);
  const inWin = winAgent.includes(k);
  if (!inLinux && !inWin) bad("agent/*", 0, `champ « ${k} » envoyé par le hub, lu par aucun agent`);
}
if (![...sent].some((k) => !linuxAgent.includes(k) && !winAgent.includes(k))) {
  ok("tous les champs du payload sont lus par au moins un agent");
}

const kinds = new Set([...certs.matchAll(/kind\)? VALUES.*?'([a-z]+)'/g)].map((m) => m[1]));
console.log(`  types de commande émis par le hub : ${[...kinds].join(", ") || "cert"}`);

// ── 5. Secrets et fichiers qui ne doivent pas être publiés ──
section("5. Secrets");
const secretPat = [
  { re: /ghp_[A-Za-z0-9]{20,}/, why: "jeton GitHub" },
  { re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/, why: "clé privée" },
  // Un libellé de formulaire ou un texte d'aide n'est pas un secret : on exige
  // une valeur qui ressemble à un mot de passe, pas à une phrase.
  { re: /(?:password|passwd|pwd|secret|token)\s*[:=]\s*["'][^"'{$ ]{8,}["']/i, why: "secret littéral" },
];
let sec = 0;
for (const f of files) {
  read(f).split("\n").forEach((l, i) => {
    for (const { re, why } of secretPat) {
      // test/ contient volontairement des données factices : les y signaler
      // rendrait le contrôle inutilisable.
      const fixture = rel(f).startsWith("test/") || /CHANGEZ|exemple|example|MotDePasse|placeholder|openssl rand|process\.env/i.test(l);
      if (re.test(l) && !fixture) {
        bad(f, i + 1, why + " → " + l.trim().slice(0, 80)); sec++;
      }
    }
  });
}
if (!sec) ok("aucun secret littéral");

console.log("\n" + "═".repeat(64));
console.log(issues === 0 ? "Aucune incohérence." : `${issues} point(s) à traiter.`);
