// A draft-07 validator covering exactly the keywords compiler/schema/policy.schema.json
// uses, and refusing anything it does not implement.
//
// The refusal is the point. This directory has no npm dependencies by design
// (compiler/README.md, invariant 7a), so the alternative to a small validator is
// no validation, and a policy that is silently half-checked is worse than one
// that is not checked at all: the driver would report "clean" on a build whose
// rules it never read. If the schema grows a keyword this does not implement,
// validation fails loudly with `unsupported keyword`, which surfaces as exit 4.

const SUPPORTED = new Set([
  '$schema', '$id', 'title', 'description', 'default', 'definitions',
  'type', 'const', 'enum', 'required', 'properties', 'additionalProperties',
  'items', 'pattern', '$ref',
]);

function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value; // 'object' | 'string' | 'number' | 'boolean'
}

function matchesType(value, name) {
  switch (name) {
    case 'null': return value === null;
    case 'array': return Array.isArray(value);
    case 'object': return value !== null && typeof value === 'object' && !Array.isArray(value);
    case 'integer': return typeof value === 'number' && Number.isInteger(value);
    case 'number': return typeof value === 'number' && Number.isFinite(value);
    case 'string': return typeof value === 'string';
    case 'boolean': return typeof value === 'boolean';
    default: return false;
  }
}

function deref(schema, root, seen = 0) {
  if (seen > 16) throw new Error('$ref nesting too deep');
  if (!schema || typeof schema !== 'object' || typeof schema.$ref !== 'string') return schema;
  const ref = schema.$ref;
  if (!ref.startsWith('#/')) throw new Error(`unsupported $ref ${ref}`);
  let node = root;
  for (const rawSeg of ref.slice(2).split('/')) {
    const seg = rawSeg.replace(/~1/g, '/').replace(/~0/g, '~');
    node = node?.[seg];
    if (node === undefined) throw new Error(`unresolvable $ref ${ref}`);
  }
  return deref(node, root, seen + 1);
}

function check(schema, value, pointer, root, errors) {
  const s = deref(schema, root);
  if (s === true) return;
  if (s === false) { errors.push({ pointer, message: 'schema forbids any value' }); return; }
  if (!s || typeof s !== 'object') return;

  for (const key of Object.keys(s)) {
    if (!SUPPORTED.has(key)) {
      errors.push({ pointer, message: `unsupported keyword \`${key}\` in schema — this validator refuses to guess` });
      return;
    }
  }

  if (s.type !== undefined) {
    const names = Array.isArray(s.type) ? s.type : [s.type];
    if (!names.some((n) => matchesType(value, n))) {
      errors.push({ pointer, message: `expected type ${names.join(' or ')}, got ${typeOf(value)}` });
      return; // further keywords would report nonsense against the wrong type
    }
  }

  if (s.const !== undefined && value !== s.const) {
    errors.push({ pointer, message: `must be ${JSON.stringify(s.const)}, got ${JSON.stringify(value)}` });
  }

  if (Array.isArray(s.enum) && !s.enum.some((c) => c === value)) {
    errors.push({ pointer, message: `must be one of ${s.enum.map((e) => JSON.stringify(e)).join(', ')}, got ${JSON.stringify(value)}` });
  }

  if (typeof s.pattern === 'string' && typeof value === 'string') {
    if (!new RegExp(s.pattern).test(value)) {
      errors.push({ pointer, message: `does not match ${s.pattern}` });
    }
  }

  const isObject = value !== null && typeof value === 'object' && !Array.isArray(value);

  if (isObject) {
    if (Array.isArray(s.required)) {
      for (const key of s.required) {
        if (!Object.prototype.hasOwnProperty.call(value, key)) {
          errors.push({ pointer, message: `missing required property \`${key}\`` });
        }
      }
    }
    const props = s.properties ?? {};
    for (const [key, sub] of Object.entries(props)) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        check(sub, value[key], `${pointer}/${key}`, root, errors);
      }
    }
    if (s.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(props, key)) {
          errors.push({ pointer, message: `unknown property \`${key}\`` });
        }
      }
    } else if (s.additionalProperties && typeof s.additionalProperties === 'object') {
      for (const key of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(props, key)) {
          check(s.additionalProperties, value[key], `${pointer}/${key}`, root, errors);
        }
      }
    }
  }

  if (Array.isArray(value) && s.items !== undefined) {
    if (Array.isArray(s.items)) {
      errors.push({ pointer, message: 'tuple-form `items` is not implemented' });
    } else {
      value.forEach((item, i) => check(s.items, item, `${pointer}/${i}`, root, errors));
    }
  }
}

/**
 * @returns {{pointer: string, message: string}[]} empty when the value validates.
 */
export function validate(schema, value) {
  const errors = [];
  try {
    check(schema, value, '', schema, errors);
  } catch (err) {
    errors.push({ pointer: '', message: err.message });
  }
  return errors;
}

export function formatErrors(errors) {
  return errors.map((e) => `${e.pointer || '(root)'}: ${e.message}`).join('\n');
}
