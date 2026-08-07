// Reading `policy.link`, and being clear about the difference between a list
// that is empty and a list that is not there.
//
// THE INTERFACE IS NOT INVENTED HERE. The `link` section already exists in
// compiler/schema/policy.schema.json:
//
//     allowedObjects       array of string
//     allowedLibraries     array of string
//     allowedLinkers       array of string
//     forbidLinkerScripts  boolean, default true
//
// and that is the whole of it. The permitted key set is read OUT OF the schema
// file at run time rather than repeated here, so that this component cannot
// drift away from the contract by being edited: if a key is added there, it is
// accepted here without a change, and if one is removed, a policy using it is
// refused here too.
//
// ABSENT IS NOT EMPTY, AND NEITHER IS "PASS"
//
//   allowedObjects: []       an explicit decision that no object is authorised.
//                            Every object in the link is a finding. This is a
//                            usable state — it is what a policy for a build
//                            that should link nothing looks like.
//   allowedObjects absent    the policy did not say. Object authorisation
//                            CANNOT BE CHECKED, so it is reported incomplete
//                            (exit 3) rather than passed. This is the whole
//                            reason exit 3 exists, and the temptation to treat
//                            an absent list as "unconstrained, therefore fine"
//                            is precisely how a checker reports clean on a
//                            build it never examined.
//   link absent entirely     nothing about the link can be checked at all.

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const SCHEMA_PATH = resolve(HERE, '..', '..', 'schema', 'policy.schema.json');

/** The keys `link` is allowed to carry, and their types, as the schema states them. */
export function readLinkSchema(schemaPath = SCHEMA_PATH) {
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
  const link = schema?.properties?.link;
  if (!link || typeof link !== 'object' || !link.properties) {
    throw new Error(`${schemaPath} has no properties.link; this component has no interface to implement against`);
  }
  const fields = {};
  for (const [k, v] of Object.entries(link.properties)) {
    fields[k] = { type: v.type, itemType: v.items?.type ?? null, default: v.default };
  }
  return { fields, additionalProperties: link.additionalProperties !== false ? true : false };
}

/**
 * Validate the `link` subtree of an already-parsed policy.
 *
 * @returns {{ok: true, link: object|null, constrained: object}
 *         | {ok: false, detail: string}}
 */
export function readLinkPolicy(policy, { schemaPath = SCHEMA_PATH } = {}) {
  let spec;
  try {
    spec = readLinkSchema(schemaPath);
  } catch (err) {
    return { ok: false, detail: err.message };
  }

  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    return { ok: false, detail: 'the policy is not a JSON object' };
  }
  if (policy.policyVersion !== 'policy-v0') {
    return { ok: false, detail: `policyVersion must be "policy-v0", got ${JSON.stringify(policy.policyVersion)}` };
  }
  const failOn = policy.failOn;
  if (!['low', 'medium', 'high', 'critical'].includes(failOn)) {
    return { ok: false, detail: `failOn must be one of low, medium, high, critical; got ${JSON.stringify(failOn)}` };
  }

  const link = policy.link;
  if (link === undefined) {
    return { ok: true, link: null, failOn, constrained: { objects: false, libraries: false, linkers: false, scripts: false } };
  }
  if (link === null || typeof link !== 'object' || Array.isArray(link)) {
    return { ok: false, detail: 'policy.link is present but is not an object' };
  }

  for (const key of Object.keys(link)) {
    if (!Object.prototype.hasOwnProperty.call(spec.fields, key) && !spec.additionalProperties) {
      return { ok: false, detail: `policy.link.${key} is not in policy.schema.json's link section; refusing rather than ignoring it, because an ignored authorisation reads as an applied one` };
    }
  }
  for (const [key, want] of Object.entries(spec.fields)) {
    if (!Object.prototype.hasOwnProperty.call(link, key)) continue;
    const got = link[key];
    if (want.type === 'array') {
      if (!Array.isArray(got)) return { ok: false, detail: `policy.link.${key} must be an array` };
      if (want.itemType === 'string' && got.some((x) => typeof x !== 'string')) {
        return { ok: false, detail: `policy.link.${key} must contain only strings` };
      }
    } else if (want.type === 'boolean' && typeof got !== 'boolean') {
      return { ok: false, detail: `policy.link.${key} must be a boolean` };
    }
  }

  return {
    ok: true,
    link,
    failOn,
    constrained: {
      objects: Array.isArray(link.allowedObjects),
      libraries: Array.isArray(link.allowedLibraries),
      linkers: Array.isArray(link.allowedLinkers),
      // The only field with a default. A policy that carries a `link` section
      // at all has, by the schema's own default, forbidden linker scripts.
      scripts: true,
    },
  };
}

/** The schema's default is `true`; absent means forbidden, not permitted. */
export function forbidLinkerScripts(link) {
  return link?.forbidLinkerScripts ?? true;
}
