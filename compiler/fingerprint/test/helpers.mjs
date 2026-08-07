// Shared loading for the fingerprint tests. Not a test file itself --
// `node --test` only collects `*.test.mjs`.

import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseModule } from '../lib/parse.mjs';
import { fingerprintFunction, allSteps, stepsWithout } from '../lib/fingerprint.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const PKG = resolve(HERE, '..');
export const TESTDATA = join(PKG, 'testdata');

export function load(name) {
  return parseModule(readFileSync(join(TESTDATA, name), 'utf8'));
}

/** Fingerprint `fn` in testdata file `name`, with all steps or a subset. */
export function fp(name, fn = '@f', steps = allSteps()) {
  return fingerprintFunction(load(name), fn, { steps }).digest;
}

export function form(name, fn = '@f', steps = allSteps()) {
  return fingerprintFunction(load(name), fn, { steps }).canonicalForm;
}

export { allSteps, stepsWithout };
