// Credentials written into the code that generated them, recognised by the
// NAME they are bound to.
//
// ── WHY THERE ARE NO PROVIDER KEY SHAPES IN THIS FILE ──────────────────────
//
// There were, and they should not have been. A corpus file is read as text by
// the scanner, so a fixture that exercises VG-SEC-005 — which recognises a key
// by its SHAPE — has to contain a real-looking one, and a real-looking one is
// what a secret scanner is built to find. GitHub opened a "publicly leaked
// secret" alert on the Google key that used to be on line 26 of this file
// within minutes of it being pushed. The key was invented here and was never
// valid, which is exactly the thing a scanner cannot know and should not have
// to guess.
//
// So the rule is absolute rather than per provider: no tracked file in this
// repository contains a string matching a provider's published key format, and
// `scripts/no-provider-key-shapes.test.mjs` keeps it that way. VG-SEC-005 is
// exercised in `packages/rules/src/rules/rules.test.ts`, where every shape is
// assembled at run time and none of them exists in a file.
//
// What is left here is the half that needs no shape: VG-SEC-003, which finds a
// secret by the name of the binding. Every line below was invisible to the
// shipped 0.3.6 engine, because `\b` cannot match between a prefix and an
// underscore.

const OPENAI_API_KEY = 'notarealkey000000000000000000000000000000';
const ANTHROPIC_API_KEY = 'notarealkey111111111111111111111111111111';
const STRIPE_SECRET = 'notarealkey222222222222222222222222222222';
const DB_PASSWORD = 'Pr0d!Passw0rd#LongEnough$42';

// A minified binding. The name carries nothing, which is precisely why
// VG-SEC-003 cannot see this one and VG-SEC-005 has to exist — see that rule's
// own tests for the shapes it recognises.
const t = 'notarealkey333333333333333333333333333333';

export default { OPENAI_API_KEY, ANTHROPIC_API_KEY, STRIPE_SECRET, DB_PASSWORD, t };
