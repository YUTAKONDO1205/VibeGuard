// Generates extensions/chrome/public/icons/icon-{16,32,48,128}.png.
//
// WHY THIS EXISTS
//
// `copy-static.mjs` writes 1×1 placeholder PNGs when `public/icons/` is empty,
// so that loading `dist/` unpacked does not warn. That placeholder shipped: the
// v0.3.0 Chrome zip carried four 68-byte 1×1 icons, i.e. a blank toolbar button.
// This script produces the real set, and keeps them reproducible rather than
// pasted-in binaries nobody can regenerate.
//
// TWO TREATMENTS, ON PURPOSE
//
//   128, 48 — the VS Code extension's artwork (`extensions/vscode/icon.png`),
//     re-cut with an alpha rounded-rect. The source is RGB with its corners
//     flattened to BLACK, which on a light surface reads as a black-cornered
//     box; the radius (32/128) is measured off the source's own arc.
//   32, 16 — a simplified silhouette of the same mark. Downscaling the artwork
//     below ~48px turns the `< >` brackets and the pulse line into noise, and at
//     16 the result is an unreadable blob. The shield outline is the one thing
//     that has to survive, so at toolbar sizes it becomes the icon's own shape.
//
// Zero dependencies (PNG decode/encode over `node:zlib`), like everything else
// in this repo.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { inflateSync, deflateSync } from 'node:zlib';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE = resolve(HERE, '../vscode/icon.png');
const OUT_DIR = resolve(HERE, 'public/icons');
const SIG = '89504e470d0a1a0a';

// ── PNG ────────────────────────────────────────────────────────────────────

/** Decode an 8-bit non-interlaced PNG (color type 2 or 6) to {w,h,rgba}. */
function decodePng(path) {
  const b = readFileSync(path);
  if (b.slice(0, 8).toString('hex') !== SIG) throw new Error(`${path}: not a PNG`);
  const w = b.readUInt32BE(16);
  const h = b.readUInt32BE(20);
  if (b[24] !== 8) throw new Error(`${path}: unsupported bit depth ${b[24]}`);
  const colorType = b[25];
  if (colorType !== 2 && colorType !== 6) throw new Error(`${path}: unsupported color type`);
  const ch = colorType === 2 ? 3 : 4;

  const idat = [];
  let off = 8;
  while (off < b.length) {
    const len = b.readUInt32BE(off);
    if (b.slice(off + 4, off + 8).toString('ascii') === 'IDAT') idat.push(b.slice(off + 8, off + 8 + len));
    off += 12 + len;
  }
  const raw = inflateSync(Buffer.concat(idat));
  const stride = w * ch;
  const out = Buffer.alloc(w * h * 4);
  let prev = Buffer.alloc(stride);
  let p = 0;
  for (let y = 0; y < h; y++) {
    const filter = raw[p++];
    const line = Buffer.from(raw.slice(p, p + stride));
    p += stride;
    for (let x = 0; x < stride; x++) {
      const a = x >= ch ? line[x - ch] : 0;
      const bb = prev[x];
      const c = x >= ch ? prev[x - ch] : 0;
      if (filter === 1) line[x] = (line[x] + a) & 0xff;
      else if (filter === 2) line[x] = (line[x] + bb) & 0xff;
      else if (filter === 3) line[x] = (line[x] + ((a + bb) >> 1)) & 0xff;
      else if (filter === 4) {
        const pp = a + bb - c;
        const pa = Math.abs(pp - a), pb = Math.abs(pp - bb), pc = Math.abs(pp - c);
        line[x] = (line[x] + (pa <= pb && pa <= pc ? a : pb <= pc ? bb : c)) & 0xff;
      } else if (filter !== 0) throw new Error(`bad PNG filter ${filter}`);
    }
    for (let x = 0; x < w; x++) {
      const s = x * ch, d = (y * w + x) * 4;
      out[d] = line[s]; out[d + 1] = line[s + 1]; out[d + 2] = line[s + 2];
      out[d + 3] = ch === 4 ? line[s + 3] : 255;
    }
    prev = line;
  }
  return { w, h, rgba: out };
}

let CRC_TABLE;
function crc32(buf) {
  if (!CRC_TABLE) {
    CRC_TABLE = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC_TABLE[n] = c;
    }
  }
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

function encodePng(path, size, rgba) {
  const stride = size * 4;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (stride + 1)] = 0;
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6; // RGBA
  writeFileSync(path, Buffer.concat([
    Buffer.from(SIG, 'hex'),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]));
}

// ── colour ─────────────────────────────────────────────────────────────────

const TO_LINEAR = new Float64Array(256);
for (let i = 0; i < 256; i++) {
  const s = i / 255;
  TO_LINEAR[i] = s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
}
function fromLinear(v) {
  const s = v <= 0.0031308 ? v * 12.92 : 1.055 * Math.pow(v, 1 / 2.4) - 0.055;
  return Math.max(0, Math.min(255, Math.round(s * 255)));
}

/** Area-average downscale in linear light, premultiplied. */
function resize(src, sw, sh, d) {
  const out = Buffer.alloc(d * d * 4);
  const xr = sw / d, yr = sh / d;
  for (let dy = 0; dy < d; dy++) {
    const y0 = dy * yr, y1 = y0 + yr;
    for (let dx = 0; dx < d; dx++) {
      const x0 = dx * xr, x1 = x0 + xr;
      let r = 0, g = 0, b = 0, a = 0, wsum = 0;
      for (let sy = Math.floor(y0); sy < Math.ceil(y1); sy++) {
        const cy = Math.min(y1, sy + 1) - Math.max(y0, sy);
        for (let sx = Math.floor(x0); sx < Math.ceil(x1); sx++) {
          const cx = Math.min(x1, sx + 1) - Math.max(x0, sx);
          const wgt = cx * cy;
          if (wgt <= 0) continue;
          const s = (sy * sw + sx) * 4;
          const al = src[s + 3] / 255;
          r += TO_LINEAR[src[s]] * al * wgt;
          g += TO_LINEAR[src[s + 1]] * al * wgt;
          b += TO_LINEAR[src[s + 2]] * al * wgt;
          a += al * wgt;
          wsum += wgt;
        }
      }
      const o = (dy * d + dx) * 4;
      if (a <= 0) continue;
      out[o] = fromLinear(r / a);
      out[o + 1] = fromLinear(g / a);
      out[o + 2] = fromLinear(b / a);
      out[o + 3] = Math.round((a / wsum) * 255);
    }
  }
  return out;
}

// ── the mark ───────────────────────────────────────────────────────────────

const SS = 4;                          // supersampling per axis
const RADIUS_RATIO = 32 / 128;         // tile corner radius, measured off the source
const TEAL = [34, 226, 235];           // the source shield's upper outline
const VIOLET = [124, 77, 235];         // its lower-left glow
const SHIELD = { shoulder: 0.48, cornerR: 0.10, tExp: 1.10, tPow: 0.90 };
const VEE = { span: 0.38, topY: 0.26, tipY: 0.68 };

const lerp = (a, b, t) => a.map((v, i) => v + (b[i] - v) * t);

/** Rounded-rect coverage in [0,1]. */
function tileCoverage(x, y, size, r) {
  let hits = 0;
  for (let sy = 0; sy < SS; sy++) {
    for (let sx = 0; sx < SS; sx++) {
      const px = x + (sx + 0.5) / SS, py = y + (sy + 0.5) / SS;
      const dx = Math.max(r - px, px - (size - r), 0);
      const dy = Math.max(r - py, py - (size - r), 0);
      if (dx * dx + dy * dy <= r * r) hits++;
    }
  }
  return hits / (SS * SS);
}

/** Shield membership, x∈[-1,1] and y∈[0,1] top→bottom. */
function inShield(x, y) {
  if (y < 0 || y > 1) return false;
  const ax = Math.abs(x);
  if (y <= SHIELD.shoulder) {
    const R = SHIELD.cornerR;
    if (y >= R || ax <= 1 - R) return ax <= 1;
    const dx = ax - (1 - R), dy = R - y;
    return dx * dx + dy * dy <= R * R;
  }
  const t = (y - SHIELD.shoulder) / (1 - SHIELD.shoulder);
  return ax <= Math.pow(Math.max(0, 1 - Math.pow(t, SHIELD.tExp)), SHIELD.tPow);
}

function distSeg(px, py, ax, ay, bx, by) {
  const vx = bx - ax, vy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * vx + (py - ay) * vy) / (vx * vx + vy * vy)));
  return Math.hypot(px - (ax + t * vx), py - (ay + t * vy));
}

/** Silhouette treatment for toolbar sizes. */
function renderSilhouette(size) {
  const rgba = Buffer.alloc(size * size * 4);
  const margin = size * 0.03;
  const cx = size / 2, halfW = size / 2 - margin, top = margin, hgt = size - margin * 2;
  const vHalf = size <= 16 ? 0.165 : 0.15; // fatter when small, or the V closes up
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let shieldA = 0, vA = 0, gradSum = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const X = px + (sx + 0.5) / SS, Y = py + (sy + 0.5) / SS;
          const nx = (X - cx) / halfW, ny = (Y - top) / hgt;
          if (!inShield(nx, ny)) continue;
          shieldA++;
          gradSum += Math.max(0, Math.min(1, ny));
          if (distSeg(nx, ny, -VEE.span, VEE.topY, 0, VEE.tipY) <= vHalf ||
              distSeg(nx, ny, VEE.span, VEE.topY, 0, VEE.tipY) <= vHalf) vA++;
        }
      }
      const cover = Math.max(0, shieldA - vA) / (SS * SS);
      if (cover <= 0) continue;
      const col = lerp(TEAL, VIOLET, shieldA ? gradSum / shieldA : 0);
      const i = (py * size + px) * 4;
      rgba[i] = Math.round(col[0]);
      rgba[i + 1] = Math.round(col[1]);
      rgba[i + 2] = Math.round(col[2]);
      rgba[i + 3] = Math.round(cover * 255);
    }
  }
  return rgba;
}

// ── main ───────────────────────────────────────────────────────────────────

const src = decodePng(SOURCE);
if (src.w !== 128 || src.h !== 128) throw new Error(`expected a 128×128 source, got ${src.w}×${src.h}`);

const master = Buffer.alloc(128 * 128 * 4);
for (let y = 0; y < 128; y++) {
  for (let x = 0; x < 128; x++) {
    const i = (y * 128 + x) * 4;
    master[i] = src.rgba[i];
    master[i + 1] = src.rgba[i + 1];
    master[i + 2] = src.rgba[i + 2];
    master[i + 3] = Math.round(tileCoverage(x, y, 128, 128 * RADIUS_RATIO) * 255);
  }
}

mkdirSync(OUT_DIR, { recursive: true });
const written = [];
for (const size of [128, 48, 32, 16]) {
  const rgba = size >= 48
    ? (size === 128 ? master : resize(master, 128, 128, size))
    : renderSilhouette(size);
  encodePng(resolve(OUT_DIR, `icon-${size}.png`), size, rgba);
  written.push(`icon-${size}.png`);
}
console.log(`[vibeguard-chrome] wrote ${written.join(', ')} → public/icons/`);
