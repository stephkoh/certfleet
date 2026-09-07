// ════════════════════════════════════════════════════════════════════
// lib/acme.js — Client ACME (RFC 8555) SANS dépendance externe.
// crypto + fetch natifs. Compte (ES256), commande, challenge DNS-01,
// génération de CSR (ASN.1/DER à la main), finalize, téléchargement.
// Agnostique du DNS : les callbacks setDns/removeDns sont injectés
// (Gandi, délégation CNAME, autre), ce module ne connaît aucun fournisseur.
// Endpoints Let's Encrypt : staging (tests, non fiable) et production.
// ════════════════════════════════════════════════════════════════════
import crypto from "node:crypto";

export const ACME_DIRECTORIES = {
  "letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
  "letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
  "zerossl":             "https://acme.zerossl.com/v2/DV90",
  "gts":                 "https://dv.acme-v02.api.pki.goog/directory",
};

const b64url = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// ── Clé de compte ACME (ES256 / P-256) ──
export function generateAccountKey() { return crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }); }
export function accountKeyToPem(kp) { return kp.privateKey.export({ type: "pkcs8", format: "pem" }); }
export function accountKeyFromPem(pem) {
  const privateKey = crypto.createPrivateKey(pem);
  const publicKey = crypto.createPublicKey(privateKey);
  return { privateKey, publicKey };
}
function accountJwk(kp) {
  const j = kp.publicKey.export({ format: "jwk" }); // {kty:'EC',crv:'P-256',x,y}
  return { crv: j.crv, kty: j.kty, x: j.x, y: j.y };
}
function jwkThumbprint(kp) {
  const j = accountJwk(kp); // ordre lexicographique imposé : crv, kty, x, y
  const json = `{"crv":"${j.crv}","kty":"${j.kty}","x":"${j.x}","y":"${j.y}"}`;
  return b64url(crypto.createHash("sha256").update(json).digest());
}
function es256Sign(kp, input) {
  return crypto.sign("sha256", Buffer.from(input), { key: kp.privateKey, dsaEncoding: "ieee-p1363" });
}

// ── Client bas niveau ──
export class AcmeClient {
  constructor({ directoryUrl, accountKey, email, log = () => {} }) {
    this.directoryUrl = directoryUrl;
    this.kp = accountKey || generateAccountKey();
    this.email = email;
    this.log = log;
    this.dir = null; this.nonce = null; this.kid = null;
  }
  async loadDirectory() { this.dir = await (await fetch(this.directoryUrl)).json(); return this.dir; }
  async newNonce() {
    const r = await fetch(this.dir.newNonce, { method: "HEAD" });
    this.nonce = r.headers.get("replay-nonce");
    return this.nonce;
  }
  async _post(url, payload) {
    if (!this.dir) await this.loadDirectory();
    if (!this.nonce) await this.newNonce();
    for (let attempt = 0; attempt < 3; attempt++) {
      const protected_ = { alg: "ES256", nonce: this.nonce, url };
      if (this.kid) protected_.kid = this.kid; else protected_.jwk = accountJwk(this.kp);
      const p64 = b64url(JSON.stringify(protected_));
      const pl64 = payload === "" ? "" : b64url(JSON.stringify(payload));
      const sig = b64url(es256Sign(this.kp, `${p64}.${pl64}`));
      const body = JSON.stringify({ protected: p64, payload: pl64, signature: sig });
      const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/jose+json" }, body });
      this.nonce = r.headers.get("replay-nonce") || this.nonce;
      const text = await r.text();
      let data = null; try { data = text ? JSON.parse(text) : null; } catch { data = text; }
      if (r.status === 400 && data && data.type && /badNonce/i.test(data.type)) { await this.newNonce(); continue; }
      if (r.status >= 400) { const e = new Error("ACME " + url + " : " + (data?.detail || data?.type || r.status)); e.status = r.status; e.body = data; throw e; }
      return { status: r.status, headers: r.headers, data };
    }
    throw new Error("ACME : trop de badNonce");
  }
  async register() {
    const { headers } = await this._post(this.dir.newAccount, {
      termsOfServiceAgreed: true, contact: this.email ? ["mailto:" + this.email] : [],
    });
    this.kid = headers.get("location");
    this.log("compte ACME : " + this.kid);
    return this.kid;
  }
  dnsTxtValue(token) {
    const keyAuth = token + "." + jwkThumbprint(this.kp);
    return b64url(crypto.createHash("sha256").update(keyAuth).digest());
  }
  async newOrder(identifiers) {
    const { headers, data } = await this._post(this.dir.newOrder, {
      identifiers: identifiers.map(v => ({ type: "dns", value: v })),
    });
    data._url = headers.get("location");
    return data;
  }
  async fetchUrl(url) { const { data } = await this._post(url, ""); return data; }              // POST-as-GET
  async completeChallenge(chUrl) { const { data } = await this._post(chUrl, {}); return data; }
  async finalize(finalizeUrl, csrDer) { const { data } = await this._post(finalizeUrl, { csr: b64url(csrDer) }); return data; }
  async downloadCert(url) { const { data } = await this._post(url, ""); return typeof data === "string" ? data : String(data); }
}

// ── Vérif de propagation DNS via DoH (DNS:53 sortant souvent filtré) ──
//
// On interroge PLUSIEURS résolveurs indépendants, et non le premier qui
// répond. Let's Encrypt valide depuis plusieurs points d'observation : il
// suffit qu'un seul tombe sur un serveur faisant autorité en retard pour que
// la validation échoue. Se fier à un seul avis revient à lancer une validation
// qu'on sait pouvoir rater.
const RESOLVEURS = [
  { nom: "Google",     url: "https://dns.google/resolve" },
  { nom: "Cloudflare", url: "https://cloudflare-dns.com/dns-query" },
  { nom: "AdGuard",    url: "https://dns.adguard-dns.com/resolve" },
];

async function dohQuery(base, name, type) {
  const r = await fetch(`${base}?name=${encodeURIComponent(name)}&type=${type}`,
    { headers: { accept: "application/dns-json" } });
  return r.json();
}

// Renvoie [{ nom, valeurs }] pour chaque résolveur ayant répondu. Un résolveur
// injoignable est simplement absent : on ne le compte ni pour ni contre.
async function dohTxtParResolveur(name) {
  const out = [];
  await Promise.all(RESOLVEURS.map(async (res) => {
    try {
      const j = await dohQuery(res.url, name, "TXT");
      out.push({
        nom: res.nom,
        valeurs: (j.Answer || []).filter(a => a.type === 16)
          .map(a => String(a.data).replace(/^"|"$/g, "").replace(/\\"/g, '"')),
      });
    } catch { /* résolveur injoignable : ignoré */ }
  }));
  return out;
}

async function dohTxt(name) {
  const avis = await dohTxtParResolveur(name);
  if (!avis.length) return null;                 // indéterminé
  return avis.flatMap(a => a.valeurs);
}

// Liste les serveurs faisant autorité, pour orienter la personne qui débogue.
async function dohNameServers(name) {
  const labels = String(name).replace(/\.$/, "").split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const zone = labels.slice(i).join(".");
    for (const res of RESOLVEURS) {
      try {
        const j = await dohQuery(res.url, zone, "NS");
        const ns = (j.Answer || []).filter(a => a.type === 2)
          .map(a => String(a.data).replace(/\.$/, ""));
        if (ns.length) return { zone, ns };
      } catch { /* suivant */ }
    }
  }
  return null;
}
// Suivi de délégation CNAME : si _acme-challenge.<domaine> est un CNAME vers une
// autre zone (ex. example.com → …dv.example.net pilotable par API), on écrit
// le TXT à la CIBLE finale. Suit jusqu'à `hops` sauts. Renvoie le nom d'origine si pas de CNAME.
export async function resolveChallengeTarget(name, { hops = 4 } = {}) {
  let cur = String(name).replace(/\.$/, "");
  for (let i = 0; i < hops; i++) {
    let found = null;
    for (const base of ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]) {
      try {
        const r = await fetch(`${base}?name=${encodeURIComponent(cur)}&type=CNAME`, { headers: { accept: "application/dns-json" } });
        const j = await r.json();
        const ans = (j.Answer || []).find(a => a.type === 5); // 5 = CNAME
        if (ans && ans.data) { found = String(ans.data).replace(/\.$/, ""); break; }
      } catch { /* essaie le résolveur suivant */ }
    }
    if (!found || found === cur) break;
    cur = found;
  }
  return cur;
}

// Interroge le SOA de la zone qui contient `name` et renvoie son champ MINIMUM,
// c'est-à-dire la durée pendant laquelle un résolveur mémorise qu'un nom
// N'EXISTE PAS. On remonte les labels jusqu'à trouver une zone qui réponde.
async function dohNegativeTtl(name) {
  const labels = String(name).replace(/\.$/, "").split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const zone = labels.slice(i).join(".");
    for (const base of ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]) {
      try {
        const r = await fetch(`${base}?name=${encodeURIComponent(zone)}&type=SOA`,
          { headers: { accept: "application/dns-json" } });
        const j = await r.json();
        const soa = (j.Answer || []).find(a => a.type === 6);
        if (!soa || !soa.data) continue;
        // Format : "<ns> <mail> <serial> <refresh> <retry> <expire> <minimum>"
        const parts = String(soa.data).trim().split(/\s+/);
        const minimum = Number(parts[parts.length - 1]);
        if (Number.isFinite(minimum) && minimum > 0) return { zone, minimum };
      } catch { /* résolveur suivant */ }
    }
  }
  return null;
}

// Enrichit l'échec de validation quand il porte la signature du cache négatif :
// notre propre vérification a vu le TXT, et Let's Encrypt répond NXDOMAIN.
// Cette combinaison n'a pas d'autre explication, et le message brut ne la donne
// pas — il coûte des heures de recherche.
async function expliquerEchecDns(recordName, erreurs, propagationVue) {
  const brut = JSON.stringify(erreurs);
  if (!propagationVue || !/NXDOMAIN/i.test(brut)) return brut;

  // Deux causes possibles, et elles n'appellent pas la même action.
  // Un désaccord entre résolveurs désigne une zone désynchronisée : attendre
  // n'y changera rien, il faut réparer la recopie entre serveurs.
  const avis = await dohTxtParResolveur(recordName).catch(() => []);
  const voient = avis.filter(a => a.valeurs.length > 0);
  if (avis.length > 1 && voient.length > 0 && voient.length < avis.length) {
    const ns = await dohNameServers(recordName).catch(() => null);
    return brut + "\n\nDIAGNOSTIC : les résolveurs publics ne sont pas d'accord. "
      + voient.map(a => a.nom).join(", ") + " voi" + (voient.length > 1 ? "ent" : "t")
      + " l'enregistrement, " + avis.filter(a => !a.valeurs.length).map(a => a.nom).join(", ")
      + " non. Les serveurs faisant autorité de cette zone ne servent donc pas le même contenu. "
      + (ns ? `Zone ${ns.zone}, serveurs : ${ns.ns.join(", ")}. Interrogez-les un par un pour repérer celui qui est en retard. ` : "")
      + "Let's Encrypt valide depuis plusieurs points d'observation : il suffit qu'un seul tombe "
      + "sur le serveur en retard pour que la validation échoue. Attendre n'y changera rien tant "
      + "que la recopie de zone entre serveurs n'est pas réparée — vérifiez le champ REFRESH du "
      + "SOA et que le primaire notifie bien ses secondaires.";
  }

  const soa = await dohNegativeTtl(recordName).catch(() => null);
  const attente = soa
    ? `Le TTL négatif de la zone ${soa.zone} est de ${soa.minimum} s`
      + ` (${Math.round(soa.minimum / 60)} min) : réessayez après ce délai,`
      + ` compté depuis la PREMIÈRE tentative ayant échoué.`
    : "Réessayez dans quelques heures, le temps que ce cache expire.";

  return brut + "\n\nDIAGNOSTIC : le TXT a bien été posé, et nos résolveurs l'ont vu. "
    + "Si Let's Encrypt répond malgré tout NXDOMAIN, c'est que SES résolveurs ont mémorisé "
    + "l'absence du nom lors d'une tentative antérieure, faite avant que la délégation "
    + "n'existe ou ne soit propagée. " + attente
    + " Relancer avant l'expiration ne changera rien : chaque essai relit le même cache. "
    + "Pour éviter cela à l'avenir, abaissez le champ MINIMUM du SOA de cette zone à 300 ou 900 secondes.";
}

// Attend que TOUS les résolveurs interrogés voient la valeur. Le désaccord
// entre eux est le symptôme d'une zone servie par des serveurs désynchronisés,
// et il est signalé explicitement : c'est une panne d'infrastructure DNS, pas
// une lenteur de propagation, et attendre davantage n'y changera rien.
async function waitDnsPropagation(name, value, { tries = 20, delay = 6000, log = () => {} } = {}) {
  let dernierDesaccord = null;

  for (let i = 0; i < tries; i++) {
    const avis = await dohTxtParResolveur(name);
    if (avis.length) {
      const voient = avis.filter(a => a.valeurs.includes(value));
      if (voient.length === avis.length) {
        log(`TXT ${name} vu par ${avis.map(a => a.nom).join(", ")} (essai ${i + 1})`);
        return true;
      }
      if (voient.length > 0) {
        dernierDesaccord = {
          oui: voient.map(a => a.nom),
          non: avis.filter(a => !a.valeurs.includes(value)).map(a => a.nom),
        };
      }
    }
    await new Promise(r => setTimeout(r, delay));
  }

  if (dernierDesaccord) {
    log(`TXT ${name} vu par ${dernierDesaccord.oui.join(", ")} mais PAS par ${dernierDesaccord.non.join(", ")}`);
    log("Les résolveurs ne sont pas d'accord : les serveurs faisant autorité de cette zone ne servent pas le même contenu.");
  } else {
    log(`TXT ${name} non confirmé après ${tries} essais — on tente quand même la validation`);
  }
  return false;
}

// ══════════ Génération de CSR (PKCS#10) en ASN.1/DER — clé RSA-2048 ══════════
function derLen(n) { if (n < 0x80) return Buffer.from([n]); const b = []; let x = n; while (x > 0) { b.unshift(x & 0xff); x >>= 8; } return Buffer.from([0x80 | b.length, ...b]); }
function tlv(tag, content) { return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]); }
const dSeq = (...i) => tlv(0x30, Buffer.concat(i));
const dSet = (...i) => tlv(0x31, Buffer.concat(i));
function dInt(n) { if (n === 0) return tlv(0x02, Buffer.from([0])); const b = []; let x = n; while (x > 0) { b.unshift(x & 0xff); x >>= 8; } if (b[0] & 0x80) b.unshift(0); return tlv(0x02, Buffer.from(b)); }
function dOid(oid) { const p = oid.split(".").map(Number); const bytes = [40 * p[0] + p[1]]; for (let i = 2; i < p.length; i++) { let v = p[i]; const st = [v & 0x7f]; v = Math.floor(v / 128); while (v > 0) { st.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); } bytes.push(...st); } return tlv(0x06, Buffer.from(bytes)); }
const dUtf8 = (s) => tlv(0x0c, Buffer.from(s, "utf8"));
const dBitStr = (buf) => tlv(0x03, Buffer.concat([Buffer.from([0]), buf]));
const dOctet = (buf) => tlv(0x04, buf);
const dCtx = (tagNum, content, constructed = true) => tlv((constructed ? 0xa0 : 0x80) | tagNum, content);
const dNull = () => tlv(0x05, Buffer.alloc(0));

// Génère une paire RSA-2048 + un CSR pour les identifiants donnés (wildcard ok).
export function generateCsr(identifiers) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const spki = publicKey.export({ type: "spki", format: "der" });
  const cn = identifiers[0];
  const subject = dSeq(dSet(dSeq(dOid("2.5.4.3"), dUtf8(cn)))); // CN
  const sanNames = Buffer.concat(identifiers.map(d => dCtx(2, Buffer.from(d, "ascii"), false))); // dNSName [2]
  const sanExt = dSeq(dOid("2.5.29.17"), dOctet(dSeq(sanNames)));
  const extReqAttr = dSeq(dOid("1.2.840.113549.1.9.14"), dSet(dSeq(sanExt)));
  const cri = dSeq(dInt(0), subject, spki, dCtx(0, extReqAttr)); // attributes [0]
  const sig = crypto.sign("sha256", cri, privateKey); // RSA-SHA256
  const sigAlg = dSeq(dOid("1.2.840.113549.1.1.11"), dNull()); // sha256WithRSAEncryption
  const csr = dSeq(cri, sigAlg, dBitStr(sig));
  return { csrDer: csr, privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }) };
}

// ══════════ Orchestration haut niveau : émettre un certificat ══════════
// setDns({ recordName, value })   → pose le TXT (recordName = _acme-challenge.<base>)
// removeDns({ recordName })       → retire le TXT
export async function issueCertificate({
  directoryUrl, accountKeyPem, identifiers, email,
  setDns, removeDns, waitDns = true, log = () => {},
}) {
  if (!identifiers || !identifiers.length) throw new Error("identifiers requis");
  const accountKey = accountKeyPem ? accountKeyFromPem(accountKeyPem) : generateAccountKey();
  const client = new AcmeClient({ directoryUrl, accountKey, email, log });
  await client.loadDirectory();
  await client.register();

  const order = await client.newOrder(identifiers);
  log(`ordre créé (${order.status}) pour ${identifiers.join(", ")}`);
  const placed = []; // TXT posés, à nettoyer

  try {
    // 1) Collecte des challenges dns-01 de toutes les autorisations
    const chs = [];
    for (const authzUrl of order.authorizations) {
      const authz = await client.fetchUrl(authzUrl);
      if (authz.status === "valid") { log(`${authz.identifier.value} déjà validé`); continue; }
      const ch = (authz.challenges || []).find(c => c.type === "dns-01");
      if (!ch) throw new Error("Pas de challenge dns-01 pour " + authz.identifier.value);
      const base = String(authz.identifier.value).replace(/^\*\./, "");
      chs.push({ authzUrl, chUrl: ch.url, identifier: authz.identifier.value,
                 recordName: "_acme-challenge." + base, value: client.dnsTxtValue(ch.token) });
    }
    // 2) Regroupe par nom : wildcard + apex partagent _acme-challenge.<domaine> avec 2 VALEURS
    //    distinctes → il faut poser TOUTES les valeurs ensemble (rrset TXT multi-valeurs).
    const byName = {};
    for (const c of chs) (byName[c.recordName] = byName[c.recordName] || []).push(c.value);
    for (const [recordName, values] of Object.entries(byName)) {
      log(`pose TXT ${recordName} = ${values.join(" , ")}`);
      await setDns({ recordName, values });
      placed.push({ recordName });
    }
    // 3) Attente de propagation (chaque valeur visible publiquement)
    // On retient si la propagation a été CONFIRMÉE : sans cette information, un
    // NXDOMAIN de Let's Encrypt peut tout aussi bien signifier que rien n'a été
    // posé. C'est la conjonction des deux qui désigne le cache négatif.
    const propagationVue = {};
    if (waitDns) {
      for (const [recordName, values] of Object.entries(byName)) {
        for (const v of values) {
          const vu = await waitDnsPropagation(recordName, v, { log });
          propagationVue[recordName] = (propagationVue[recordName] !== false) && vu;
        }
      }
    }
    // 4) Déclenche toutes les validations
    for (const c of chs) await client.completeChallenge(c.chUrl);
    // 5) Attend que CHAQUE autorisation devienne valide
    for (const c of chs) {
      let ok = false;
      for (let i = 0; i < 40; i++) {
        const a = await client.fetchUrl(c.authzUrl);
        if (a.status === "valid") { log(`${c.identifier} validé`); ok = true; break; }
        if (a.status === "invalid") {
          const erreurs = a.challenges?.map(x => x.error).filter(Boolean);
          const detail = await expliquerEchecDns(c.recordName, erreurs, propagationVue[c.recordName] === true);
          throw new Error("Validation échouée pour " + c.identifier + " : " + detail);
        }
        await new Promise(r => setTimeout(r, 4000));
      }
      if (!ok) throw new Error("Timeout de validation pour " + c.identifier);
    }

    const { csrDer, privateKeyPem } = generateCsr(identifiers);
    let fin = await client.finalize(order.finalize, csrDer);
    for (let i = 0; i < 30 && fin.status !== "valid"; i++) {
      await new Promise(r => setTimeout(r, 3000));
      fin = await client.fetchUrl(order._url);
      if (fin.status === "invalid") throw new Error("Finalize échoué : " + JSON.stringify(fin));
    }
    if (fin.status !== "valid") throw new Error("Ordre non finalisé (timeout)");
    const pemChain = await client.downloadCert(fin.certificate);
    log("certificat téléchargé");

    // Découpe la chaîne : 1er bloc = feuille, le reste = chaîne intermédiaire
    const blocks = pemChain.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
    const leafPem = blocks[0] || "";
    const chainPem = blocks.slice(1).join("\n");
    let notAfter = null, notBefore = null, issuer = null, serial = null, fingerprint = null;
    try {
      const x = new crypto.X509Certificate(leafPem);
      notAfter = new Date(x.validTo).toISOString(); notBefore = new Date(x.validFrom).toISOString();
      issuer = x.issuer; serial = x.serialNumber;
      fingerprint = x.fingerprint256;
    } catch { /* best effort */ }

    return {
      leafPem, chainPem, fullchainPem: [leafPem, chainPem].filter(Boolean).join("\n"),
      privateKeyPem, accountKeyPem: accountKeyToPem(accountKey),
      notAfter, notBefore, issuer, serial, fingerprint, identifiers,
    };
  } finally {
    for (const p of placed) { try { await removeDns({ recordName: p.recordName }); log("TXT retiré " + p.recordName); } catch (e) { log("nettoyage TXT échoué " + p.recordName + " : " + e.message); } }
  }
}
