// ═══════════════════════════════════════════════════════════════════
// make-avatar.mjs — génère le logo en PNG, sans dépendance.
//
// Le dessin est décrit par des fonctions de distance signée puis rendu en
// suréchantillonnage 4× avant réduction, ce qui donne des bords lisses sans
// bibliothèque graphique. zlib et crypto suffisent à écrire le PNG.
//
//   node assets/make-avatar.mjs
// ═══════════════════════════════════════════════════════════════════
import zlib from "node:zlib";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const OUT = path.dirname(fileURLToPath(import.meta.url));
const SS = 4;                                   // facteur de suréchantillonnage

// ── Palette ──────────────────────────────────────────────────────────
const BG_TOP    = [0x0b, 0x3d, 0x91];
const BG_BOTTOM = [0x12, 0x56, 0xc4];
const WHITE     = [0xff, 0xff, 0xff];
const GREEN     = [0x22, 0xc5, 0x5e];

// ── Distances signées ────────────────────────────────────────────────
// Négatif = à l'intérieur de la forme.
const roundedRect = (x, y, cx, cy, w, h, r) => {
  const dx = Math.abs(x - cx) - (w / 2 - r);
  const dy = Math.abs(y - cy) - (h / 2 - r);
  const ax = Math.max(dx, 0), ay = Math.max(dy, 0);
  return Math.hypot(ax, ay) + Math.min(Math.max(dx, dy), 0) - r;
};

// Anneau : le cadenas n'a que la moitié haute de l'anse, d'où le découpage en y.
const arc = (x, y, cx, cy, radius, thickness) =>
  Math.abs(Math.hypot(x - cx, y - cy) - radius) - thickness / 2;

// Segment épais, pour les branches de l'anse et les traits de la coche.
function segment(x, y, ax, ay, bx, by, thickness) {
  const vx = bx - ax, vy = by - ay;
  const wx = x - ax, wy = y - ay;
  const t = Math.max(0, Math.min(1, (wx * vx + wy * vy) / (vx * vx + vy * vy)));
  return Math.hypot(wx - t * vx, wy - t * vy) - thickness / 2;
}

// ── Composition d'un pixel ───────────────────────────────────────────
// N = côté de l'image finale ; les coordonnées sont normalisées sur 512 pour
// que le dessin reste identique quelle que soit la taille demandée.
function shade(px, py, N) {
  const s = N / 512;
  const x = px / s, y = py / s;                 // repère de référence, 512×512

  // Fond : dégradé vertical dans un carré à coins arrondis.
  const bg = roundedRect(x, y, 256, 256, 512, 512, 112);
  if (bg > 0.5) return null;                    // hors du carré : transparent

  const t = y / 512;
  let col = [
    BG_TOP[0] + (BG_BOTTOM[0] - BG_TOP[0]) * t,
    BG_TOP[1] + (BG_BOTTOM[1] - BG_TOP[1]) * t,
    BG_TOP[2] + (BG_BOTTOM[2] - BG_TOP[2]) * t,
  ];
  let alpha = bg <= 0 ? 1 : 0;

  const put = (d, rgb) => { if (d <= 0) col = rgb.slice(); };

  // Anse du cadenas : demi-anneau supérieur prolongé par deux branches droites.
  const ringD = arc(x, y, 256, 214, 82, 34);
  if (y <= 214) put(ringD, WHITE);
  put(segment(x, y, 174, 214, 174, 252, 34), WHITE);
  put(segment(x, y, 338, 214, 338, 252, 34), WHITE);

  // Corps du cadenas.
  const body = roundedRect(x, y, 256, 330, 268, 190, 34);
  put(body, WHITE);

  // Coche verte gravée dans le corps : c'est elle qui dit « vérifié », et non
  // simplement « chiffré » — la nuance que fait certfleet en resondant la cible.
  if (body <= 0) {
    const c1 = segment(x, y, 205, 332, 243, 370, 30);
    const c2 = segment(x, y, 243, 370, 312, 296, 30);
    put(Math.min(c1, c2), GREEN);
  }

  return [col[0], col[1], col[2], alpha];
}

// ── Rendu ────────────────────────────────────────────────────────────
function render(N) {
  const rgba = Buffer.alloc(N * N * 4);
  const inv = 1 / (SS * SS);

  for (let y = 0; y < N; y++) {
    for (let x = 0; x < N; x++) {
      let r = 0, g = 0, b = 0, a = 0;
      // Suréchantillonnage : SS×SS points par pixel, moyennés.
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const c = shade(x + (sx + 0.5) / SS, y + (sy + 0.5) / SS, N);
          if (!c) continue;
          r += c[0] * c[3]; g += c[1] * c[3]; b += c[2] * c[3]; a += c[3];
        }
      }
      const i = (y * N + x) * 4;
      if (a > 0) {
        // Couleur non prémultipliée, pour un PNG correct sur fond clair comme sombre.
        rgba[i]     = Math.round(r / a);
        rgba[i + 1] = Math.round(g / a);
        rgba[i + 2] = Math.round(b / a);
        rgba[i + 3] = Math.round(a * inv * 255);
      }
    }
  }
  return rgba;
}

// ── Écriture du PNG ──────────────────────────────────────────────────
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = -1;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function writePng(file, rgba, N) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(N, 0);
  ihdr.writeUInt32BE(N, 4);
  ihdr[8] = 8;    // 8 bits par canal
  ihdr[9] = 6;    // RGBA
  // 10-12 : compression, filtre, entrelacement — tous à 0.

  // Chaque ligne est préfixée de son type de filtre ; 0 = aucun.
  const raw = Buffer.alloc(N * (N * 4 + 1));
  for (let y = 0; y < N; y++) {
    raw[y * (N * 4 + 1)] = 0;
    rgba.copy(raw, y * (N * 4 + 1) + 1, y * N * 4, (y + 1) * N * 4);
  }

  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
  fs.writeFileSync(file, png);
  return png.length;
}

for (const N of [512, 256, 128]) {
  const file = path.join(OUT, `avatar-${N}.png`);
  const bytes = writePng(file, render(N), N);
  console.log(`${path.basename(file)}  ${N}×${N}  ${(bytes / 1024).toFixed(1)} Ko`);
}
