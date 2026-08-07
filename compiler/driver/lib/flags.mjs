// flags.required / flags.forbidden / flags.optLevels.
//
// Matching is deliberately narrow and written down, because a flag check whose
// matching rule is "whatever `includes` does" fails in both directions at once:
// `-O2` matches inside `-O2x`, and `-fstack-protector` does not match
// `-fstack-protector-strong`. Neither failure is visible in a green build.

import { CFG, makeFinding } from './findings.mjs';
import { OPT_LEVELS, parseOverrideEnv } from './cmdline.mjs';

/**
 * A pattern matches a token when:
 *   - they are equal;                                  `-O2`
 *   - the pattern ends `=` and the token starts with it; `-fsanitize=`
 *   - the pattern ends `*` and the token starts with the rest. `-fstack-protector*`
 *
 * Nothing else. In particular a bare `-fstack-protector` does not match
 * `-fstack-protector-strong`: those are different flags with different
 * behaviour, and a policy that meant the family says so with `*`.
 */
export function tokenMatches(token, pattern) {
  if (typeof token !== 'string' || typeof pattern !== 'string') return false;
  if (token === pattern) return true;
  if (pattern.endsWith('=') && pattern.length > 1) return token.startsWith(pattern);
  if (pattern.endsWith('*') && pattern.length > 1) return token.startsWith(pattern.slice(0, -1));
  return false;
}

export function firstMatch(tokens, pattern) {
  for (const t of tokens) if (tokenMatches(t, pattern)) return t;
  return null;
}

/**
 * @param {ReturnType<import('./cmdline.mjs').normalise>} normalised
 * @param {object} policy
 * @returns {{findings: object[], detail: object}}
 */
export function checkFlags(normalised, policy, env = {}) {
  const findings = [];
  const flags = policy.flags ?? {};
  const where = { kind: 'invocation', path: normalised.sources[0] ?? null, unit: null, pass: null };

  // The command line clang compiles is argv edited by CCC_OVERRIDE_OPTIONS, so
  // that is the command line the policy is about. Reading argv alone leaves a
  // route by which every check here answers about a build that did not happen.
  const override = parseOverrideEnv(env.CCC_OVERRIDE_OPTIONS);
  const envTokens = [...override.prepend, ...override.append];
  const space = envTokens.length > 0 ? [...normalised.matchSpace, ...envTokens] : normalised.matchSpace;
  const envOptLevels = envTokens.filter((t) => OPT_LEVELS.has(t) || t === '-O');

  if (override.opaque) {
    findings.push(makeFinding({
      id: CFG.COMMAND_LINE_UNRECOVERABLE,
      // Low on purpose, and the exit code does not come from here. This is not
      // "we found a violation" — it is "we cannot tell", which is exit 3, and
      // `complete: false` below is what produces it. Filing it at a severity
      // that trips the failure threshold would report an unread command line as
      // a finding about the build, which is a different and untrue sentence.
      severity: 'low',
      title: 'The command line was edited from the environment in a way this check cannot replay',
      detail: 'CCC_OVERRIDE_OPTIONS carries a rewrite or delete operator, so the tokens clang '
        + 'actually compiled cannot be recovered without replaying its own edit. The flag checks '
        + 'below are reported as incomplete rather than as having passed.',
      where,
    }));
  }

  const requiredResults = [];
  for (const pattern of flags.required ?? []) {
    const hit = firstMatch(space, pattern);
    requiredResults.push({ pattern, present: hit !== null });
    if (hit === null) {
      findings.push(makeFinding({
        id: CFG.REQUIRED_FLAG_MISSING,
        severity: 'high',
        title: 'A flag the policy requires is not in the normalised command line',
        detail: `flags.required lists \`${pattern}\`; no token in the normalised command line matches it.`,
        where,
      }));
    }
  }

  const forbiddenResults = [];
  for (const pattern of flags.forbidden ?? []) {
    const hit = firstMatch(space, pattern);
    forbiddenResults.push({ pattern, present: hit !== null, token: hit });
    if (hit !== null) {
      const viaCc1 = normalised.cc1Tokens.includes(hit);
      const viaLinker = normalised.linkerTokens.includes(hit);
      const route = viaCc1 ? ' (reached through -Xclang)' : viaLinker ? ' (reached through -Wl,/-Xlinker)' : '';
      findings.push(makeFinding({
        id: CFG.FORBIDDEN_FLAG,
        severity: 'high',
        title: 'The command line carries a flag the policy forbids',
        detail: `flags.forbidden lists \`${pattern}\`; the command line has \`${hit}\`${route}.`,
        where,
      }));
    }
  }

  // Optimisation level. An empty `optLevels` means the policy did not
  // constrain it; a non-empty one means the properties in this policy were
  // observed at those levels and nowhere else.
  const optLevelResult = { configured: Array.isArray(flags.optLevels) && flags.optLevels.length > 0, effective: null, allowed: flags.optLevels ?? [] };

  // Order matters and is not the order the tokens were written in: `^X`
  // prepends, argv sits in the middle, `+X` appends, and clang takes the last
  // `-O` in that assembled line. An appended `-O0` therefore beats an argv
  // `-O2`, which is exactly the case that made this necessary.
  const normaliseLevel = (t) => (t === '-O' ? '-O1' : t);
  const orderedLevels = [
    ...override.prepend.filter((t) => OPT_LEVELS.has(t) || t === '-O').map(normaliseLevel),
    ...normalised.optLevels,
    ...override.append.filter((t) => OPT_LEVELS.has(t) || t === '-O').map(normaliseLevel),
  ];
  optLevelResult.fromEnvironment = envOptLevels.length > 0;

  if (optLevelResult.configured) {
    // clang takes the last -O on the line; no -O at all is -O0.
    const effective = orderedLevels.length > 0 ? orderedLevels[orderedLevels.length - 1] : '-O0';
    optLevelResult.effective = effective;
    if (!flags.optLevels.includes(effective)) {
      findings.push(makeFinding({
        id: CFG.OPT_LEVEL_NOT_EVALUATED,
        severity: 'medium',
        title: 'Compiled at an optimisation level this policy has not been evaluated at',
        detail: `effective level is ${effective}; flags.optLevels is [${flags.optLevels.join(', ')}]. `
          + 'A property observed to survive one level has not been observed to survive another.',
        where,
      }));
    }
  } else if (orderedLevels.length > 0) {
    optLevelResult.effective = orderedLevels[orderedLevels.length - 1];
  } else {
    optLevelResult.effective = '-O0';
  }

  return {
    findings,
    // False when the command line could not be recovered. The caller turns this
    // into exit 3, because "the forbidden flag was not there" and "we could not
    // tell whether it was there" are different sentences and only one of them
    // is a pass.
    complete: !override.opaque,
    detail: {
      required: requiredResults,
      forbidden: forbiddenResults,
      optLevel: optLevelResult,
      environmentOverride: {
        present: override.present,
        recoverable: !override.opaque,
        prepended: override.prepend,
        appended: override.append,
      },
    },
  };
}
