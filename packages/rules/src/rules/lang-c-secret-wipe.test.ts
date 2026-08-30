// VG-MEM-006 — the cast form and the two-tier secret vocabulary.
//
// Every positive here is a shape that was OBSERVED in generated C and that this
// rule silently missed before, and every negative is a shape the widened rule
// could plausibly start flagging and must not. The corpus, the protocol and the
// recall numbers are in `compiler/eval/ai-generated/`.
//
// The measured miss rate that motivated this file: of 174 generated files that
// wiped a secret with a removable `memset`, the rule reported 91. Of the 83 it
// missed, 77 were inside its own declared scope — the argument did name a
// secret. Two independent defects produced that: a vocabulary that did not
// contain the words the models used, and a pattern that admitted `&` but not a
// cast.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import type { RuleContext } from '../rule-types.js';
import { cInsecureSecretWipe } from './lang-c.js';

function ctx(content: string, language = 'c'): RuleContext {
  return { content, lines: content.split('\n'), language };
}
const run = (src: string) => cInsecureSecretWipe.match(ctx(src));
const n = (src: string) => run(src).length;

describe('VG-MEM-006 cast form', () => {
  it('still flags the plain and address-of forms', () => {
    expect(n('memset(key, 0, sizeof(key));')).toBe(1);
    expect(n('memset(&key, 0, sizeof key);')).toBe(1);
  });

  // The three spellings taken verbatim from the measured corpus.
  it('flags a wipe behind a cast', () => {
    expect(n('memset((void *)password, 0, sizeof(password));')).toBe(1);
    expect(n('memset((volatile unsigned char *)key, 0, sizeof(key));')).toBe(1);
    expect(n('memset((unsigned char *)key, 0, sizeof(key));')).toBe(1);
  });

  it('flags cast spellings the corpus did not happen to contain', () => {
    expect(n('memset((void*)key, 0, 32);')).toBe(1);
    expect(n('memset((char **)key, 0, n);')).toBe(1);
    expect(n('memset( ( void * ) secret , 0 , n );')).toBe(1);
    expect(n('memset((void *)&key, 0, sizeof key);')).toBe(1);
  });

  it('reports the identifier, not the cast, as the evidence', () => {
    const [m] = run('memset((volatile unsigned char *)key, 0, sizeof(key));');
    expect(m?.evidence).toBe('memset(key, 0, ...)');
  });

  it('does not treat a non-zero fill as a wipe, cast or not', () => {
    expect(n('memset(key, 1, sizeof key);')).toBe(0);
    expect(n('memset((void *)key, 0xAA, sizeof key);')).toBe(0);
  });

  it('does not match a call whose name merely ends in memset', () => {
    expect(n('xmemset(key, 0, n);')).toBe(0);
    expect(n('secure_memset(key, 0, n);')).toBe(0);
  });
});

describe('VG-MEM-006 first-tier vocabulary keeps its confidence', () => {
  it('reports a first-tier word without a per-match override', () => {
    const [m] = run('memset(password, 0, sizeof password);');
    expect(m).toBeDefined();
    expect(m?.confidence).toBeUndefined();
  });
});

describe('VG-MEM-006 second-tier vocabulary', () => {
  // Words the models actually used for a secret, with the counts they were
  // missed at: sk (20), pin (19), seed and its compounds (23), premaster (9).
  it.each([
    ['memset(pin, 0, sizeof(pin));'],
    ['memset(seed, 0, sizeof seed);'],
    ['memset(seed_phrase, 0, sizeof seed_phrase);'],
    ['memset(seed_buffer, 0, sizeof seed_buffer);'],
    ['memset(premaster, 0, 48);'],
    ['memset((void *)pin, 0, sizeof(pin));'],
  ])('flags %s', (src) => {
    expect(n(src)).toBe(1);
  });

  it('marks a second-tier match as low confidence', () => {
    const [m] = run('memset(pin, 0, sizeof(pin));');
    expect(m?.confidence).toBe('low');
  });

  // A sibling word in the SAME identifier that argues the thing is not a secret.
  it.each([
    ['memset(random_seed, 0, sizeof random_seed);'],
    ['memset(rng_seed, 0, sizeof rng_seed);'],
    ['memset(xorshift_seed, 0, sizeof xorshift_seed);'],
    ['memset(world_seed, 0, sizeof world_seed);'],
    ['memset(flood_seed, 0, sizeof flood_seed);'],
    ['memset(gpio_pin, 0, sizeof gpio_pin);'],
    ['memset(pin_config, 0, sizeof pin_config);'],
    ['memset(led_pin_map, 0, sizeof led_pin_map);'],
    ['memset(relay_pin, 0, sizeof relay_pin);'],
    ['memset(row_pin, 0, sizeof row_pin);'],
    ['memset(col_pin, 0, sizeof col_pin);'],
    ['memset(scan_pin_history, 0, sizeof scan_pin_history);'],
    ['memset(sk_buff, 0, sizeof sk_buff);'],
    ['memset(sk_sock, 0, sizeof sk_sock);'],
  ])('stays silent on %s', (src) => {
    expect(n(src)).toBe(0);
  });

  // Vetoes are written singular and identifiers are not.
  it.each([
    ['memset(pin_states, 0, sizeof pin_states);'],
    ['memset(pin_modes, 0, sizeof pin_modes);'],
    ['memset(pin_configs, 0, sizeof pin_configs);'],
  ])('stays silent on the plural %s', (src) => {
    expect(n(src)).toBe(0);
  });
});

// `sk` is the one second-tier word whose collision is with an unrelated domain
// AND whose commonest spelling has no sibling to veto: kernel code writes a bare
// `sk` for a socket and control code writes `Sk` for the Kalman innovation
// covariance. It is gated on the file looking like it handles secrets at all.
describe('VG-MEM-006 sk needs the file to be about secrets', () => {
  it('flags sk in a file that signs', () => {
    const src = [
      'void ed25519_sign(const unsigned char sk[64], const unsigned char *m, unsigned long n, unsigned char sig[64]);',
      'int sign_it(unsigned char *msg, unsigned long n, unsigned char sig[64]) {',
      '  unsigned char sk[64];',
      '  ed25519_sign(sk, msg, n, sig);',
      '  memset(sk, 0, sizeof(sk));',
      '  return 0;',
      '}',
    ].join('\n');
    expect(n(src)).toBe(1);
  });

  it('stays silent on the kernel socket idiom', () => {
    const src = [
      'struct sock { int sk_state; };',
      'struct foo_sock { struct sock sk; unsigned seq; };',
      'void foo_sock_recycle(struct foo_sock *fs) {',
      '  memset(&fs->sk, 0, sizeof(fs->sk));',
      '}',
      'void foo_sock_init(struct sock *sk) {',
      '  memset(sk, 0, sizeof(struct foo_sock));',
      '}',
    ].join('\n');
    expect(n(src)).toBe(0);
  });

  it('stays silent on a Kalman filter', () => {
    const src = [
      'static float Sk[3][3];',
      'static float Pk[3][3];',
      'void ekf_begin_update(void) {',
      '  memset(Sk, 0, sizeof(Sk));',
      '  memset(Pk, 0, sizeof(Pk));',
      '}',
    ].join('\n');
    expect(n(src)).toBe(0);
  });

  // The context test cannot be anchored on \b: C joins words with `_`, which is
  // a word character, so \bed25519\b does not match inside `ed25519_sign`.
  it.each([
    ['ed25519_sign', 'void ed25519_sign(unsigned char *p);\nvoid f(void){unsigned char sk[64];ed25519_sign(sk);memset(sk,0,64);}'],
    ['sign_with_private_key', 'int sign_with_private_key(char *p);\nvoid f(void){unsigned char sk[64];sign_with_private_key((char*)sk);memset(sk,0,64);}'],
    ['aes256_encrypt', 'void aes256_encrypt(unsigned char *p);\nvoid f(void){unsigned char sk[32];aes256_encrypt(sk);memset(sk,0,32);}'],
  ])('finds the context inside an underscore-joined identifier: %s', (_l, src) => {
    expect(n(src)).toBe(1);
  });
});

describe('VG-MEM-006 does not carry vkey', () => {
  // The Win32 name for the 256-byte virtual-key state array GetKeyboardState()
  // fills. Two detections across 720 generations was not worth firing on every
  // input handler.
  it('stays silent on the Win32 virtual-key array', () => {
    const src = [
      'typedef unsigned char BYTE;',
      'int GetKeyboardState(BYTE *state);',
      'static BYTE vkey[256];',
      'void input_begin_frame(void) {',
      '  memset(vkey, 0, sizeof(vkey));',
      '}',
    ].join('\n');
    expect(n(src)).toBe(0);
  });
});

describe('VG-MEM-006 must not learn the scratch-buffer name', () => {
  it('stays silent on buf and buffer', () => {
    expect(n('memset(buf, 0, sizeof(buf));')).toBe(0);
    expect(n('memset(buffer, 0, sizeof(buffer));')).toBe(0);
    expect(n('memset((void *)buf, 0, sizeof(buf));')).toBe(0);
  });

  // The behavioural half of the same guard. A pin test on the word list can pass
  // while the rule still fires through some other path, so the standing negative
  // control is scanned as a file.
  it('reports nothing on the standing negative control file', () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const control = resolve(
      here,
      '../../../../samples/crossfile-fixtures/embedded-real-api/main.c',
    );
    const src = readFileSync(control, 'utf8');
    expect(src).toContain('memset(buf, 0, sizeof(buf));');
    expect(cInsecureSecretWipe.match(ctx(src)).length).toBe(0);
  });
});

describe('VG-MEM-006 stays linear', () => {
  // The A1 work found 21 of 47 rules breaking a three-second contract on cubic
  // inputs. The cast group adds an optional run, so it gets its own budget here.
  // This lives in a test FILE on purpose: the same check written as `node -e`
  // loses backslashes through the shell and passes for the wrong reason.
  it.each([
    ['open paren then spaces', 'memset(' + ' '.repeat(20000) + ',0,'],
    ['nested open parens', 'memset(' + '('.repeat(20000)],
    ['unterminated type blob', 'memset((' + 'a'.repeat(20000) + ',0,'],
    ['type words without a star', 'memset((' + 'a '.repeat(10000) + '*)x,0,'],
    ['star run', 'memset((void ' + '*'.repeat(20000) + ')x,0,'],
    ['long identifier', 'memset(' + 'a'.repeat(20000) + ',0,'],
    ['many casts', 'memset((void *)key, 0, n);'.repeat(4000)],
  ])('handles %s within budget', (_label, src) => {
    const t0 = Date.now();
    cInsecureSecretWipe.match(ctx(src));
    expect(Date.now() - t0).toBeLessThan(3000);
  });
});
