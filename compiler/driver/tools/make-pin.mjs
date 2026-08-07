#!/usr/bin/env node
// Generate a toolchain pin from what is installed on this machine.
//
//   node tools/make-pin.mjs --out <path> [--root /] [--cc clang-18] [--cxx clang++-18]
//                           [--also lld-18 --also llvm-config-18]
//
// A pin is a claim about bytes, so this reads the bytes rather than asking the
// package manager. `dpkg -S` would give the version faster and would keep
// giving it after someone rebuilt the binary in place.
//
// This is a convenience for setting up a fixture. It is not part of the driver:
// nothing in lib/ imports it, and a pin generated on one machine is not
// expected to verify on another — that is what pinning means.

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';

function parseArgs(argv) {
  const out = { out: null, root: '/', cc: 'clang-18', cxx: 'clang++-18', also: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--out') out.out = argv[++i];
    else if (a === '--root') out.root = argv[++i];
    else if (a === '--cc') out.cc = argv[++i];
    else if (a === '--cxx') out.cxx = argv[++i];
    else if (a === '--also') out.also.push(argv[++i]);
    else throw new Error(`unknown argument ${a}`);
  }
  if (!out.out) throw new Error('--out is required');
  return out;
}

function which(name) {
  if (isAbsolute(name)) return name;
  return execFileSync('sh', ['-c', `command -v ${JSON.stringify(name)}`], { encoding: 'utf8' }).trim();
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function dpkgVersion(path) {
  try {
    const pkg = execFileSync('dpkg', ['-S', path], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
      .split(':')[0].trim();
    return execFileSync('dpkg-query', ['-W', '-f=${Version}', pkg], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || null;
  } catch {
    return null;
  }
}

const args = parseArgs(process.argv.slice(2));
const root = resolve(args.root);
const names = [args.cc, args.cxx, ...args.also];

const packages = [];
for (const name of names) {
  const abs = which(name);
  const rel = relative(root, abs).split('\\').join('/');
  packages.push({
    name: name.split('/').pop(),
    path: rel,
    sha256: sha256(abs),
    version: dpkgVersion(abs),
  });
}

const ccAbs = which(args.cc);
const versionText = execFileSync(ccAbs, ['--version'], { encoding: 'utf8' });
const m = /clang version (\d+\.\d+\.\d+)/.exec(versionText);
if (!m) throw new Error(`could not read a clang version out of:\n${versionText}`);

const pin = {
  pinVersion: 'toolchain-pin-v0',
  clang: m[1],
  root: args.root,
  drivers: {
    cc: relative(root, ccAbs).split('\\').join('/'),
    cxx: relative(root, which(args.cxx)).split('\\').join('/'),
  },
  packages,
};

mkdirSync(dirname(resolve(args.out)), { recursive: true });
writeFileSync(resolve(args.out), `${JSON.stringify(pin, null, 2)}\n`, 'utf8');
process.stderr.write(`wrote pin for clang ${pin.clang} with ${packages.length} package(s)\n`);
