import { describe, expect, it } from 'vitest';
import type { RuleContext, RuleDefinition } from '../rule-types.js';
import { extractBlockAfter } from '../matcher-utils.js';
import { cGets, cUnboundedCopy, cMemcpyFromStrlen, cDoubleFree, cUseAfterFree } from './lang-c.js';
import {
  embWifiCredential,
  embNamedSecretLiteral,
  embCleartextHttp,
  embSecretToSerial,
  embRemoveBeforeProdComment,
} from './embedded-ai.js';
import { rtosForbiddenApiInIsr, rtosVolatileLeak, rtosODirectNoSync } from './embedded-rtos.js';
import { embUseBeforeBegin } from './embedded-ai.js';

function ctx(content: string, language = 'cpp'): RuleContext {
  return { content, lines: content.split('\n'), language };
}
function n(rule: RuleDefinition, content: string): number {
  return rule.match(ctx(content)).length;
}

describe('VG-MEM negatives (safe idioms must not flag)', () => {
  it('MEM-001 flags gets but not fgets', () => {
    expect(n(cGets, 'gets(buf);')).toBe(1);
    expect(n(cGets, 'fgets(buf, sizeof(buf), stdin);')).toBe(0);
  });
  it('MEM-002 flags strcpy but not strncpy / snprintf', () => {
    expect(n(cUnboundedCopy, 'strcpy(a, b);')).toBe(1);
    expect(n(cUnboundedCopy, 'strncpy(a, b, sizeof(a));')).toBe(0);
    expect(n(cUnboundedCopy, 'snprintf(a, sizeof(a), "%s", b);')).toBe(0);
  });
  it('MEM-004 does not flag the classic branch-guarded free (control flow between)', () => {
    // if (err) { free(x); return; } ... free(x);  — a `}`/return sits between.
    expect(n(cDoubleFree, 'if (err) { free(x); return -1; }\nfree(x);')).toBe(0);
    // free then reassign then free is also fine.
    expect(n(cDoubleFree, 'free(x); x = malloc(8); free(x);')).toBe(0);
    // genuine straight-line double free flags.
    expect(n(cDoubleFree, 'free(x);\nfree(x);')).toBe(1);
  });
  it('MEM-005 does not flag the free-then-null idiom', () => {
    expect(n(cUseAfterFree, 'free(x); x = NULL;\nx->field;')).toBe(0);
    expect(n(cUseAfterFree, 'free(x);\nx->field = 1;')).toBe(1);
  });
});

describe('VG-EMB negatives', () => {
  it('EMB-001 flags literal credentials but not the provisioned (variable) form', () => {
    expect(n(embWifiCredential, 'WiFi.begin("Net", "hunter2pw");')).toBe(1);
    expect(n(embWifiCredential, 'WiFi.begin(ssid, pw);')).toBe(0);
  });
  it('EMB-010 flags non-loopback http but exempts localhost/127.0.0.1', () => {
    expect(n(embCleartextHttp, 'http.begin("http://api.example.com/x");')).toBe(1);
    expect(n(embCleartextHttp, 'http.begin("http://localhost:8080/x");')).toBe(0);
    expect(n(embCleartextHttp, 'http.begin("http://127.0.0.1/x");')).toBe(0);
    expect(n(embCleartextHttp, 'http.begin("https://api.example.com/x");')).toBe(0);
  });
  it('EMB-022 flags a secret var but not a prompt string literal', () => {
    expect(n(embSecretToSerial, 'Serial.println(password);')).toBe(1);
    expect(n(embSecretToSerial, 'Serial.println("Enter password:");')).toBe(0);
  });
});

describe('VG-RTOS-001 body scoping', () => {
  it('flags forbidden calls inside an ISR body', () => {
    expect(n(rtosForbiddenApiInIsr, 'void IRAM_ATTR h() { Serial.println("x"); }')).toBe(1);
    expect(n(rtosForbiddenApiInIsr, 'ISR(TIMER1_OVF_vect) { malloc(4); }')).toBe(1);
  });
  it('does not flag the same calls OUTSIDE an interrupt handler', () => {
    expect(n(rtosForbiddenApiInIsr, 'void loop() { Serial.println("x"); malloc(4); }')).toBe(0);
  });
  it('does not flag the correct FromISR variant or delayMicroseconds', () => {
    expect(
      n(rtosForbiddenApiInIsr, 'void IRAM_ATTR h() { xQueueSendFromISR(q, &v, NULL); }'),
    ).toBe(0);
    expect(n(rtosForbiddenApiInIsr, 'void IRAM_ATTR h() { delayMicroseconds(5); }')).toBe(0);
  });
});

// Regression pins for the false positives found by adversarial review and fixed.
describe('adversarial-review regressions (must stay fixed)', () => {
  it('MEM-004 ignores mutually-exclusive else branches', () => {
    expect(n(cDoubleFree, 'if (a) free(p); else free(p);')).toBe(0);
  });
  it('MEM-001/002 do not fire inside block comments or string literals', () => {
    expect(n(cGets, 'x();\n/* gets(buf) is banned */')).toBe(0);
    expect(n(cUnboundedCopy, 'x();\n/* never use strcpy(d, s) */')).toBe(0);
    expect(n(cUnboundedCopy, 'log("use strcpy here");')).toBe(0);
    // real calls still fire
    expect(n(cGets, 'gets(b);')).toBe(1);
    expect(n(cUnboundedCopy, 'strcpy(d, s);')).toBe(1);
    expect(n(cMemcpyFromStrlen, 'memcpy(d, s, strlen(s));')).toBe(1);
  });
  it('MEM-005 does not treat a deref inside a string as a use', () => {
    expect(n(cUseAfterFree, 'free(p);\nprintf("p->x was %d", saved);')).toBe(0);
  });
  it('EMB-002 requires a delimited credential keyword (no COMPASS/PIN/ssid FPs)', () => {
    expect(n(embNamedSecretLiteral, '#define COMPASS_ID "north-1"')).toBe(0);
    expect(n(embNamedSecretLiteral, '#define PIN_MAPPING "D1:led"')).toBe(0);
    expect(n(embNamedSecretLiteral, 'const char* ssid = "MyHomeNetwork";')).toBe(0);
    expect(n(embNamedSecretLiteral, '#define WIFI_PASSWORD "s3cr3t-home"')).toBe(1);
  });
  it('EMB-001 filters YOUR_/changeme placeholders (prefix semantics)', () => {
    expect(n(embWifiCredential, 'WiFi.begin("YOUR_SSID", "YOUR_PASSWORD");')).toBe(0);
    expect(n(embWifiCredential, 'WiFi.begin("net", "changeme123");')).toBe(0);
    expect(n(embWifiCredential, 'WiFi.begin("Home", "hunter2pw");')).toBe(1);
  });
  it('EMB-023 Japanese branch requires a comment marker', () => {
    expect(n(embRemoveBeforeProdComment, 'printf("本番環境ではこの機能は無効です");')).toBe(0);
    expect(n(embRemoveBeforeProdComment, 'x(); // 本番環境では消す')).toBe(1);
  });
  it('RTOS-001 does not bind to the function after a forward declaration', () => {
    expect(n(rtosForbiddenApiInIsr, 'void IRAM_ATTR onTimer();\nvoid setup() { Serial.begin(9600); }')).toBe(0);
  });
  it('RTOS-001 counts a body reached by two heads only once (ESP32 pattern)', () => {
    expect(
      n(rtosForbiddenApiInIsr, 'void IRAM_ATTR h() { malloc(4); }\nvoid setup() { attachInterrupt(0, h, RISING); }'),
    ).toBe(1);
  });
  it('RTOS-001 ignores forbidden tokens inside comments/strings in the ISR body', () => {
    expect(n(rtosForbiddenApiInIsr, 'void IRAM_ATTR h() { /* Serial.println("x") old */ flag = 1; }')).toBe(0);
  });
  it('RTOS-004 does not fire when O_SYNC is already present (either order)', () => {
    expect(n(rtosODirectNoSync, 'open(p, O_DIRECT | O_SYNC);')).toBe(0);
    expect(n(rtosODirectNoSync, 'open(p, O_SYNC | O_DIRECT);')).toBe(0);
    expect(n(rtosODirectNoSync, 'open(p, O_DIRECT);')).toBe(1);
  });
});

describe('VG-RTOS-002 volatile-leak (conservative)', () => {
  it('flags a non-volatile file-scope scalar written in an ISR and read outside', () => {
    expect(n(rtosVolatileLeak, 'int c=0;\nvoid IRAM_ATTR h(){c++;}\nvoid loop(){if(c>1)c=0;}')).toBe(1);
  });
  it('stays silent for volatile, body-local, write-only, and undeclared', () => {
    expect(n(rtosVolatileLeak, 'volatile int c=0;\nvoid IRAM_ATTR h(){c++;}\nvoid loop(){if(c>1)c=0;}')).toBe(0);
    expect(n(rtosVolatileLeak, 'void IRAM_ATTR h(){int s=0;s++;}')).toBe(0);
    expect(n(rtosVolatileLeak, 'int c=0;\nvoid IRAM_ATTR h(){c++;}')).toBe(0); // no outside read
    expect(n(rtosVolatileLeak, 'void IRAM_ATTR h(){c++;}\nvoid loop(){x=c;}')).toBe(0); // no decl
    expect(n(rtosVolatileLeak, 'int c=0;\nvoid IRAM_ATTR h(){obj.c++;}\nvoid loop(){x=c;}')).toBe(0); // member
  });
  it('does not flag a global shadowed by a same-named ISR-body local (line-start decl)', () => {
    const shadow =
      'int count = 0;\nvoid IRAM_ATTR h() {\n  int count = 0;\n  count++;\n}\nvoid loop() { if (count > 1) count = 0; }';
    expect(n(rtosVolatileLeak, shadow)).toBe(0);
  });
});

describe('VG-EMB-031 use-before-begin (same body only)', () => {
  it('flags a use before begin() in the same setup body', () => {
    expect(n(embUseBeforeBegin, 'void setup(){ Serial.println("x"); Serial.begin(9600); }')).toBe(1);
  });
  it('does not flag correct order, begin-in-setup/use-in-loop, or begin-absent', () => {
    expect(n(embUseBeforeBegin, 'void setup(){ Serial.begin(9600); Serial.println("x"); }')).toBe(0);
    expect(n(embUseBeforeBegin, 'void setup(){ Serial.begin(9600); }\nvoid loop(){ Serial.println("x"); }')).toBe(0);
    expect(n(embUseBeforeBegin, 'void setup(){ Serial.println("x"); }')).toBe(0);
  });
});

describe('extractBlockAfter', () => {
  const body = (s: string, from = 0) => extractBlockAfter(s, from)?.body ?? null;
  it('returns the balanced block', () => {
    expect(body('f() { a; { b; } c; }')).toBe('{ a; { b; } c; }');
  });
  it('ignores braces inside strings and comments', () => {
    expect(body('f() { s = "}"; /* } */ // }\n}')).toBe('{ s = "}"; /* } */ // }\n}');
  });
  it('honors escaped quotes', () => {
    expect(body('f() { s = "\\"}"; }')).toBe('{ s = "\\"}"; }');
  });
  it('returns null on an unbalanced block (fail quiet)', () => {
    expect(body('f() { a; { b; ')).toBeNull();
  });
  it('returns null when no brace is within the head gap', () => {
    expect(extractBlockAfter('int x = 1;', 0)).toBeNull();
  });
});
