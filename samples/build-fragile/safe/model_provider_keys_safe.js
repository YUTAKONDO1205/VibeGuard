// The same six credentials, none of them in the file.
//
// The pairing matters for the shape rule in particular: a `.env.example` style
// placeholder has the same prefix as a real key, and a rule that cannot tell
// them apart is a rule nobody leaves switched on.

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const STRIPE_SECRET = process.env.STRIPE_SECRET;
const DB_PASSWORD = process.env.DB_PASSWORD;

// Documentation placeholders. Same prefixes, obviously not credentials.
// No placeholder key shapes either: a documentation placeholder still MATCHES
// a provider's format, and a secret scanner reads a format, not an intention.
// The placeholder cases live in the rule's own tests, assembled at run time.
const EXAMPLE_NOTE = 'see packages/rules/src/rules/rules.test.ts for placeholder handling';


export default {
  OPENAI_API_KEY,
  ANTHROPIC_API_KEY,
  STRIPE_SECRET,
  DB_PASSWORD,
  EXAMPLE_NOTE,
};
