#!/usr/bin/env node
// Generate an ed25519 signing key pair.
//
//   node tools/keygen.mjs --dir <directory> [--name signing-key] [--force]
//
// No key is generated into the source tree and no key is committed. The tests
// call `writeKeyPair` into a temporary directory and delete it afterwards; this
// executable exists so that a human doing the same thing by hand does not
// invent a different key format.
//
// Refuses to overwrite an existing private key without `--force`: a signing key
// silently replaced is every previously issued signature silently invalidated,
// and the failure shows up somewhere else entirely.

import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { EXIT_INCOMPLETE, EXIT_OK } from '../../driver/lib/exit.mjs';
import { parseArgv } from '../lib/cli.mjs';
import { writeKeyPair } from '../lib/keys.mjs';

const args = parseArgv(process.argv.slice(2));

if (args.has('help') || args.has('h')) {
  process.stdout.write('usage: keygen.mjs --dir <directory> [--name signing-key] [--force]\n');
  process.exit(EXIT_OK);
}

const dir = args.get('dir');
if (typeof dir !== 'string' || dir.length === 0) {
  process.stderr.write('--dir <directory> is required. A key pair has to be put somewhere on purpose.\n');
  process.exit(EXIT_INCOMPLETE);
}
const name = typeof args.get('name') === 'string' ? args.get('name') : 'signing-key';

if (!args.has('force') && existsSync(join(dir, `${name}.pem`))) {
  process.stderr.write(
    `${name}.pem already exists in that directory. Replacing a signing key invalidates every\n`
    + 'signature it made, so this needs --force to be an explicit decision.\n',
  );
  process.exit(EXIT_INCOMPLETE);
}

const pair = writeKeyPair(dir, { name });
process.stdout.write(`keyId=${pair.keyId}\n`);
process.stdout.write(`private=${name}.pem\n`);
process.stdout.write(`public=${name}.pub.pem\n`);
if (!pair.privateModeApplied) {
  process.stdout.write(
    'note: owner-only permissions were not applied to the private key on this platform. '
    + 'Protect it with the filesystem\'s own access control.\n',
  );
}
process.exit(EXIT_OK);
