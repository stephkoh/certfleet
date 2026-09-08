// ═══════════════════════════════════════════════════════════════════
// test/smoke.mjs — vérifications sans base de données.
// Crypto du coffre, ACME, sonde, catalogue de cibles, cohérence de l'agent.
//   npm run test:smoke
// ═══════════════════════════════════════════════════════════════════
import assert from "node:assert";
import fs from "node:fs";
import crypto from "node:crypto";

// Le coffre exige une clé : on en fournit une jetable avant tout import.
process.env.CERT_VAULT_KEY ||= crypto.randomBytes(32).toString("base64");
process.env.DATABASE_URL ||= "postgres://x:x@127.0.0.1:1/x";

const { vaultEncrypt, vaultDecrypt, vaultKeyIsExternal } = await import("../src/lib/vault.js");
const { generateAccountKey, accountKeyToPem, accountKeyFromPem, generateCsr, ACME_DIRECTORIES } =
  await import("../src/lib/acme.js");
const { expiryStatus, TLS_KINDS } = await import("../src/lib/certprobe.js");
const { TARGET_TYPES, _certRecipients, _SEUILS_ALERTE } = await import("../src/routes/certificates.js");
const { hashPassword, verifyPassword, passwordProblem } = await import("../src/auth.js");
const { roleFromGroups } = await import("../src/lib/ldap.js");

let n = 0;
const t = async (name, fn) => {
  try { await fn(); n++; console.log("  ok   " + name); }
  catch (e) { console.log("  FAIL " + name + " -> " + e.message); process.exitCode = 1; }
};

console.log("coffre");
await t("clé externe détectée", () => assert.strictEqual(vaultKeyIsExternal(), true));
await t("aller-retour AES-256-GCM", async () => {
  const s = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----";
  const b = await vaultEncrypt(s);
  assert.notStrictEqual(b, s, "le chiffré ne doit pas être le clair");
  assert.strictEqual(await vaultDecrypt(b), s);
});
await t("chiffrement non déterministe (IV aléatoire)", async () =>
  assert.notStrictEqual(await vaultEncrypt("x"), await vaultEncrypt("x")));
await t("blob altéré rejeté (GCM authentifié)", async () => {
  const b = await vaultEncrypt("secret");
  await assert.rejects(() => vaultDecrypt(b.slice(0, -6) + (b.slice(-6) === "AAAAAA" ? "BBBBBB" : "AAAAAA")));
});

console.log("mots de passe");
await t("scrypt : vérification correcte", () => {
  const h = hashPassword("MotDePasseTest1234");
  assert.ok(verifyPassword("MotDePasseTest1234", h));
  assert.ok(!verifyPassword("MotDePasseTest1235", h));
});
await t("sel différent à chaque hachage", () =>
  assert.notStrictEqual(hashPassword("x"), hashPassword("x")));
await t("hachage corrompu rejeté sans lever d'exception", () => {
  assert.strictEqual(verifyPassword("x", "n'importe quoi"), false);
  assert.strictEqual(verifyPassword("x", null), false);
});
await t("politique de mot de passe", () => {
  assert.ok(passwordProblem("court"), "trop court doit être refusé");
  assert.ok(passwordProblem("motdepasseminuscule"), "sans majuscule ni chiffre doit être refusé");
  assert.strictEqual(passwordProblem("MotDePasseTest1234"), null);
});

console.log("rôles");
await t("le rôle le plus fort l'emporte", () => {
  const groups = ["CN=lecteurs,OU=G,DC=x", "CN=admins,OU=G,DC=x"];
  const map = [{ group: "lecteurs", role: "viewer" }, { group: "admins", role: "admin" }];
  assert.strictEqual(roleFromGroups(groups, map, "viewer"), "admin");
});
await t("correspondance sur le DN complet", () => {
  assert.strictEqual(
    roleFromGroups(["CN=ops,OU=G,DC=x"], [{ group: "CN=ops,OU=G,DC=x", role: "operator" }], "viewer"),
    "operator");
});
await t("sans correspondance, rôle par défaut", () =>
  assert.strictEqual(roleFromGroups(["CN=autre,DC=x"], [{ group: "ops", role: "admin" }], "viewer"), "viewer"));

console.log("acme");
await t("clé de compte ES256, aller-retour PEM", () => {
  const pem = accountKeyToPem(generateAccountKey());
  assert.ok(pem.includes("PRIVATE KEY"));
  assert.ok(accountKeyFromPem(pem));
});
await t("CSR multi-domaines : DER valide et SAN présent", () => {
  const { csrDer, privateKeyPem } = generateCsr(["exemple.fr", "www.exemple.fr"]);
  assert.ok(privateKeyPem.includes("BEGIN PRIVATE KEY"));
  assert.ok(Buffer.isBuffer(csrDer) && csrDer.length > 300);
  assert.strictEqual(csrDer[0], 0x30, "doit débuter par une SEQUENCE DER");
  assert.ok(csrDer.includes(Buffer.from("www.exemple.fr", "ascii")), "SAN absent du CSR");
});
await t("annuaires ACME tous en https", () => {
  const u = Object.values(ACME_DIRECTORIES).map(v => (typeof v === "string" ? v : v.url));
  assert.ok(u.length && u.every(x => x.startsWith("https://")));
});

console.log("sonde");
await t("seuils d'expiration", () => {
  const at = d => new Date(Date.now() + d * 864e5).toISOString();
  assert.strictEqual(expiryStatus(at(-1)).status, "expired");
  assert.strictEqual(expiryStatus(at(3)).status, "critical");
  assert.strictEqual(expiryStatus(at(14)).status, "warning");
  assert.strictEqual(expiryStatus(at(120)).status, "ok");
  assert.strictEqual(expiryStatus(null).status, "unknown");
});
await t("types TLS déclarés", () => assert.ok(Object.keys(TLS_KINDS).length >= 3));

console.log("connecteurs");
await t("catalogue de cibles cohérent", () => {
  const ids = TARGET_TYPES.map(x => x.type);
  for (const need of ["nginx", "haproxy", "aloha", "servu", "iis", "exchange", "f5", "vsftpd", "k8s_secret"])
    assert.ok(ids.includes(need), "type manquant : " + need);
  assert.strictEqual(new Set(ids).size, ids.length, "types dupliqués");
  for (const ty of TARGET_TYPES) {
    assert.ok(ty.label && Array.isArray(ty.fields) && ty.fields.length, "type incomplet : " + ty.type);
    for (const f of ty.fields) assert.ok(f.key && f.label && f.type, "champ incomplet dans " + ty.type);
  }
  console.log("       " + TARGET_TYPES.length + " types de cible");
});

console.log("canal des secrets");
await t("les secrets de cible ne voyagent pas en clair", async () => {
  const crypto = await import("node:crypto");
  const fs = await import("node:fs");

  // Le hub chiffre les paramètres sensibles avec la MÊME clé AES que la clé
  // privée : ils ne doivent apparaître ni dans le code, ni en clair ailleurs.
  const src = fs.readFileSync("src/routes/certificates.js", "utf8");
  assert.ok(src.includes("secrets_cipher"), "canal chiffré absent du hub");
  assert.ok(/for \(const k of Object\.keys\(extra\)\) if \(k\.endsWith\("_enc"\)\) delete extra\[k\]/.test(src),
    "les valeurs chiffrées au repos partent quand même vers l'agent");

  // Aller-retour AES-256-CBC, tel que l'agent le fait.
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const secrets = { storepass: "MotDePasseKeystore#2026" };
  const c = crypto.createCipheriv("aes-256-cbc", key, iv);
  const blob = Buffer.concat([c.update(JSON.stringify(secrets), "utf8"), c.final()]);
  const d = crypto.createDecipheriv("aes-256-cbc", key, iv);
  const back = JSON.parse(Buffer.concat([d.update(blob), d.final()]).toString("utf8"));
  assert.strictEqual(back.storepass, secrets.storepass);
  assert.ok(!blob.toString("latin1").includes("MotDePasse"), "le clair transparaît dans le chiffré");
});
await t("tout champ « password » du catalogue est chiffré au repos", async () => {
  const fs = await import("node:fs");
  const src = fs.readFileSync("src/routes/certificates.js", "utf8");
  assert.ok(src.includes("const SECRET_FIELDS = new Set("), "liste des champs secrets absente");
  assert.ok(!/if \(p\.password != null/.test(src), "le chiffrement est resté limité au seul champ password");
});
const passwordFields = TARGET_TYPES.flatMap(t2 => (t2.fields || []).filter(f => f.type === "password").map(f => t2.type + "." + f.key));
console.log("       champs sensibles : " + passwordFields.join(", "));

console.log("agent");
await t("les scripts servis par le hub existent", () => {
  const src = fs.readFileSync("src/routes/agents.js", "utf8");
  const names = [...src.matchAll(/sendScript\(res,\s*"([^"]+)"/g)].map(m => m[1]);
  assert.ok(names.length >= 2, "aucun script servi");
  for (const nm of names) assert.ok(fs.existsSync("agent/" + nm), "agent/" + nm + " introuvable");
  console.log("       " + names.join(", "));
});
await t("le helper appelé par l'agent est bien celui livré", () => {
  const a = fs.readFileSync("agent/certfleet-agent.sh", "utf8");
  const called = [...a.matchAll(/\/usr\/local\/bin\/(certfleet-[a-z-]+)/g)].map(m => m[1]);
  assert.ok(called.includes("certfleet-cert-install"), "helper non appelé");
  assert.ok(fs.existsSync("agent/certfleet-cert-install"));
});

console.log("alertes");
await t("analyse des adresses de destination", () => {
  assert.deepStrictEqual(_certRecipients("a@b.fr"), ["a@b.fr"]);
  assert.deepStrictEqual(_certRecipients("a@b.fr, c@d.fr"), ["a@b.fr", "c@d.fr"]);
  assert.deepStrictEqual(_certRecipients("a@b.fr;c@d.fr"), ["a@b.fr", "c@d.fr"]);
  assert.deepStrictEqual(_certRecipients(" a@b.fr  a@b.fr "), ["a@b.fr"], "doublon non éliminé");
  assert.deepStrictEqual(_certRecipients(["x@y.fr", null, "z@w.io"]), ["x@y.fr", "z@w.io"]);
  // une adresse invalide ne doit pas empêcher les autres de recevoir l'alerte
  assert.deepStrictEqual(_certRecipients("bon@ok.fr, pasuneadresse"), ["bon@ok.fr"]);
  assert.deepStrictEqual(_certRecipients(""), []);
  assert.deepStrictEqual(_certRecipients(null), []);
});
await t("les paliers d'expiration relancent bien à chaque étape", () => {
  const palier = j => (j < 0 ? "expire" : _SEUILS_ALERTE.find(x => j <= x));
  // Le piège : classés en décroissant, .find() renvoie toujours le plus grand
  // seuil, une seule alerte part à 30 j et plus rien ensuite jusqu'à l'expiration.
  assert.strictEqual(palier(90), undefined, "alerte trop tôt");
  assert.strictEqual(palier(31), undefined, "alerte trop tôt");
  assert.strictEqual(palier(30), 30);
  assert.strictEqual(palier(15), 30);
  assert.strictEqual(palier(14), 14, "pas de relance à 14 j");
  assert.strictEqual(palier(7), 7, "pas de relance à 7 j");
  assert.strictEqual(palier(3), 3, "pas de relance à 3 j");
  assert.strictEqual(palier(1), 1, "pas de relance à 1 j");
  assert.strictEqual(palier(0), 1);
  assert.strictEqual(palier(-2), "expire", "certificat expiré non signalé");
  // chaque palier doit produire une clé distincte, sinon la relance est avalée
  const cles = new Set([30, 15, 14, 8, 7, 4, 3, 1, 0, -2].map(palier));
  assert.strictEqual(cles.size, 6, "paliers confondus : des relances seront perdues");
});

console.log("\n" + n + " tests passés");
