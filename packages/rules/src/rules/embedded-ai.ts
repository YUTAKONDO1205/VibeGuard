// vibeguard:disable-file VG-EMB-010 VG-EMB-020 VG-QUAL-009 VG-AUTH-003
// This file DEFINES the embedded-AI rules; the literal tokens and phrases
// (`http://`, `#define DEBUG 1`, `setInsecure()`, "remove before production",
// and the `changeme`/`dummy`/`placeholder` PLACEHOLDER allowlist) appear inside
// regex sources and remediation prose by design, so the file must not flag itself.
//
// VG-EMB 17e EMB-AI — AI-generated embedded code, the family no existing static
// analyzer fires on (languages ['c','cpp']). THIS IS THE STAR of VG-EMB.
//
// WHY EXISTING TOOLS STAY SILENT HERE, AND VIBEGUARD DOES NOT: flawfinder /
// cppcheck / clang-tidy reason about C SEMANTICS — undefined behaviour, buffer
// bounds, unchecked returns. A hard-coded Wi-Fi password is perfectly valid C;
// `WiFi.begin("home", "hunter2")` has no UB and no memory error, so those tools
// say nothing. But it is the single most common thing an LLM emits when asked
// for firmware, because its training corpus is tutorials that inline the
// credentials. The overlap with existing embedded static analysis is therefore
// STRUCTURALLY near-zero — this family is defined by "valid code that is a
// security problem because of WHO wrote it and WHY", which is the VG-AISC thesis.
//
// DECLARED BOUNDARIES (lexical rules cannot decide these; forcing them would
// manufacture the false positives E3=0 forbids — each is an honest limit of a
// lexical approach, listed rather than hidden):
//   - CRC-misused-as-integrity: whether a CRC guards corruption (fine) or
//     authenticity (broken) is a semantic property no window can read.
//   - Entropy/"does this flash string look secret": that is a classifier, not a
//     rule. Only NAME-keyed secrets are detected here.
//   - Init-order across functions/files, power-management ordering: dataflow.
import type { RuleDefinition, RuleMatch } from '../rule-types.js';
import {
  runRegex,
  indexToPosition,
  extractBlockAfter,
  blankCommentsAndStrings,
  REGEX_INPUT_CAP,
} from '../matcher-utils.js';

/** Placeholder credentials. PREFIX semantics, matching the VG-SEC-003
 *  convention (secrets.ts:62) — so `YOUR_PASSWORD`, `changeme123`, etc. are
 *  filtered by their leading token, not only when they equal it exactly. */
const PLACEHOLDER = /^(?:changeme|change_me|changethis|dummy|placeholder|your|xxxx|example|test|123456|admin|password|secret|mypass|foobar|<|\.\.\.|\*)/i;

function lastLiteral(evidence: string): string {
  return evidence.match(/"([^"]*)"\s*$/)?.[1] ?? '';
}

// ---- Family 1: hard-coded secrets (category 'secrets'; skipCommentLines is
// OMITTED per the secrets convention — a key in a comment is still a leak; the
// auto context-confidence layer down-ranks comment placement rather than
// dropping it). --------------------------------------------------------------

export const embWifiCredential: RuleDefinition = {
  ruleId: 'VG-EMB-001',
  name: 'Hard-coded Wi-Fi credentials',
  description:
    'WiFi.begin / softAP / addAP called with two string LITERALS — the SSID and password baked into the firmware image. AI-generated sketches ship this constantly.',
  languages: ['c', 'cpp'],
  category: 'secrets',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-798'],
  tags: ['embedded', 'ai-prone', 'arduino'],
  remediation: {
    why: 'The password is in the flashed binary and in version control forever; anyone with the firmware or the repo has the Wi-Fi credentials.',
    how: 'Provision credentials at runtime — read them from NVS / Preferences / a config partition set during manufacturing, not from a string literal.',
    exampleFix: 'WiFi.begin(prefs.getString("ssid").c_str(), prefs.getString("pw").c_str());',
  },
  // Both args must be string literals; the provisioned form WiFi.begin(ssid, pw)
  // with variables does not match. Each variable run is separated by a literal.
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\b(?:WiFi\.begin|WiFi\.softAP|wifiMulti\.addAP)[ \t]{0,8}\([ \t]{0,8}"[^"\n]{0,120}"[ \t]{0,8},[ \t]{0,8}"[^"\n]{1,120}"/g,
      { language: ctx.language },
    ).filter((m) => !PLACEHOLDER.test(lastLiteral(m.evidence))),
};

export const embNamedSecretLiteral: RuleDefinition = {
  ruleId: 'VG-EMB-002',
  name: 'Secret assigned to a credential-named identifier',
  description:
    'A #define or variable whose name contains password / psk / secret / api_key / pin is assigned a string literal. Catches short Wi-Fi PSKs that the entropy-based VG-SEC-003 (20-char floor) misses — the embedded-specific gap.',
  languages: ['c', 'cpp'],
  category: 'secrets',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-798'],
  tags: ['embedded', 'ai-prone'],
  remediation: {
    why: 'A credential in a #define or PROGMEM array is compiled into the image; it cannot be rotated without reflashing and is visible to anyone who dumps the flash.',
    how: 'Store credentials in a provisioned config region (NVS / Preferences / a secure element), not in a source literal.',
  },
  match: (ctx) => [
    // #define form. The credential keyword must be a DELIMITED identifier
    // segment (start of name, or after `_`) so `COMPASS_ID` (PASS inside
    // COMPASS) and `PIN_MAPPING`/`SPINDLE` do not match. `PIN` is dropped
    // entirely: GPIO pin defines are ubiquitous and are not secrets (a real BLE
    // PIN is caught by VG-EMB-003).
    ...runRegex(
      ctx.content,
      /^[ \t]{0,20}#[ \t]{0,8}define[ \t]{1,8}(?:[A-Za-z0-9]{1,20}_){0,6}(?:PASSWORD|PASS|PSK|SECRET|TOKEN|API_?KEY)(?:_[A-Za-z0-9]{1,20}){0,6}[ \t]{1,8}"[^"\n]{1,120}"/gim,
      { language: ctx.language },
    ),
    // Variable-assignment form. `ssid` is dropped (an SSID is broadcast, not a
    // secret; a hard-coded SSID+password pair is caught by VG-EMB-001).
    ...runRegex(
      ctx.content,
      /\b\w{0,24}(?:password|passwd|psk|secret|api_?key|apikey)\w{0,10}[ \t]{0,8}(?:\[[ \t\d]{0,8}\][ \t]{0,8})?(?:PROGMEM[ \t]{1,8})?=[ \t]{0,8}"[^"\n]{1,120}"/gi,
      { language: ctx.language },
    ),
  ].filter((m) => !PLACEHOLDER.test(lastLiteral(m.evidence))),
};

export const embStaticBlePasskey: RuleDefinition = {
  ruleId: 'VG-EMB-003',
  name: 'Static BLE pairing passkey',
  description:
    'A fixed BLE passkey / static PIN is set in source. A hard-coded passkey defeats the point of the pairing exchange — anyone who reads the firmware can pair.',
  languages: ['c', 'cpp'],
  category: 'auth',
  severity: 'medium',
  defaultConfidence: 'medium',
  cwe: ['CWE-798', 'CWE-1391'],
  tags: ['embedded', 'ble', 'ai-prone'],
  remediation: {
    why: 'A static passkey is the same on every device and is recoverable from one firmware dump, so BLE pairing provides no authentication.',
    how: 'Use a per-device random passkey shown out-of-band, or a pairing method with device-unique keys.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\bset(?:StaticPIN|Passkey)[ \t]{0,8}\([ \t]{0,8}\d{4,8}\b|\b(?:ESP_)?BLE_SM_SET_STATIC_PASSKEY\b/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

// ---- Family 2: communication downgrade (category 'crypto'; skipCommentLines is
// ON — these are code rules and a doc-comment URL must not fire). -------------

export const embCleartextHttp: RuleDefinition = {
  ruleId: 'VG-EMB-010',
  name: 'Cleartext HTTP endpoint from device',
  description:
    'A "http://" URL literal (non-loopback) used by an embedded HTTP client. Firmware talking plaintext over the network exposes everything it sends and lets an on-path attacker rewrite responses (and OTA payloads).',
  languages: ['c', 'cpp'],
  category: 'crypto',
  severity: 'medium',
  defaultConfidence: 'medium',
  cwe: ['CWE-319'],
  tags: ['embedded', 'ai-prone'],
  remediation: {
    why: 'Plaintext HTTP on a device has no confidentiality or integrity: credentials, telemetry, and firmware updates can be read and altered on the wire.',
    how: 'Use https:// with certificate validation (setCACert / a pinned root). If the endpoint is truly local and trusted, keep it off any routable network.',
  },
  // Requires the opening quote, and exempts loopback. Prose URLs on comment
  // lines are dropped by skipCommentLines; inline ones need the quote.
  match: (ctx) =>
    runRegex(
      ctx.content,
      /"http:\/\/(?!localhost[/:"]|127\.0\.0\.1)[^"\n]{1,200}"/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const embTlsVerificationDisabled: RuleDefinition = {
  ruleId: 'VG-EMB-011',
  name: 'TLS certificate verification disabled',
  description:
    'setInsecure(), skip_cert_common_name_check, or MBEDTLS_SSL_VERIFY_NONE turns off certificate validation, so TLS provides encryption but no authentication — trivially MITM-able. Nearly always a true positive in shipped firmware and invisible to C-semantics analyzers.',
  languages: ['c', 'cpp'],
  category: 'crypto',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-295'],
  tags: ['embedded', 'ai-prone', 'tls'],
  remediation: {
    why: 'Without certificate validation any server can impersonate the real one; the TLS session is encrypted to the attacker. AI code reaches for setInsecure() the moment a cert error appears.',
    how: 'Install the server\'s CA (setCACert with the root PEM) or pin the certificate. Never ship setInsecure() / VERIFY_NONE.',
    exampleFix: 'client.setCACert(root_ca_pem);',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\bsetInsecure[ \t]{0,8}\([ \t]{0,8}\)|\bskip_cert_common_name_check[ \t]{0,8}=[ \t]{0,8}true\b|\bMBEDTLS_SSL_VERIFY_NONE\b/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const embBleJustWorks: RuleDefinition = {
  ruleId: 'VG-EMB-012',
  name: 'BLE Just Works / no-MITM pairing constant',
  description:
    'A specific weak BLE pairing constant (ESP_LE_AUTH_(NO_)BOND without MITM, ESP_IO_CAP_NONE, BLE_HS_IO_NO_INPUT_OUTPUT) selects "Just Works" pairing, which provides no MITM protection.',
  languages: ['c', 'cpp'],
  category: 'crypto',
  severity: 'medium',
  defaultConfidence: 'low',
  cwe: ['CWE-1391'],
  tags: ['embedded', 'ble'],
  remediation: {
    why: 'Just Works pairing has no authentication step, so an attacker can MITM the pairing and every subsequent exchange. Acceptable only for a device that transfers nothing sensitive.',
    how: 'Use a pairing method with MITM protection (passkey entry or numeric comparison) via an IO capability other than NONE.',
  },
  // Presence-test of specific weak constants only. Never inferred from the
  // ABSENCE of MITM flags — that would be the overreach that breaks E3.
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\bsetAuthenticationMode[ \t]{0,8}\([ \t]{0,8}ESP_LE_AUTH_(?:NO_BOND|BOND)[ \t]{0,8}\)|\bESP_IO_CAP_NONE\b|\bBLE_HS_IO_NO_INPUT_OUTPUT\b/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

// ---- Family 3: debug remnants (category 'ai-quality' / 'auth' / 'logging'). --

export const embDebugDefineOn: RuleDefinition = {
  ruleId: 'VG-EMB-020',
  name: '#define DEBUG 1 left on in firmware',
  description:
    'A debug flag hard-defined ON. In a shipped build this enables verbose logging, debug endpoints, and often relaxed checks. Mirrors the web-side VG-QUAL-008 for C/C++.',
  languages: ['c', 'cpp'],
  category: 'ai-quality',
  severity: 'medium',
  defaultConfidence: 'medium',
  tags: ['embedded', 'ai-prone'],
  remediation: {
    why: 'Debug-on ships internal state (and sometimes bypasses) to anyone with a serial cable or network access to the device.',
    how: 'Default the debug flag OFF and gate it behind a build type: #define DEBUG 0, or select it from the build system for dev builds only.',
    exampleFix: '#define DEBUG 0',
  },
  // skipCommentLines ON: a commented-out `// #define DEBUG 1` is the FIXED state.
  match: (ctx) =>
    runRegex(
      ctx.content,
      /^[ \t]{0,20}#[ \t]{0,8}define[ \t]{1,8}(?:DEBUG|DEBUG_MODE|ENABLE_DEBUG|DEBUG_ENABLED|VERBOSE(?:_DEBUG)?)[ \t]{1,8}(?:1|true|TRUE)\b/gm,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const embAuthBypassFlag: RuleDefinition = {
  ruleId: 'VG-EMB-021',
  name: 'Auth / security bypass flag',
  description:
    'A BYPASS/SKIP/DISABLE_AUTH-style flag defined ON, or branched on. A test bypass that reaches production disables the check entirely.',
  languages: ['c', 'cpp'],
  category: 'auth',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-489'],
  tags: ['embedded', 'ai-prone'],
  remediation: {
    why: 'A shipped bypass flag is a backdoor: whoever knows it (and it is in the firmware) skips authentication or verification entirely.',
    how: 'Remove the bypass path. If a test hook is genuinely needed, gate it behind a build type that cannot be selected for release, not a runtime flag.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /#[ \t]{0,8}define[ \t]{1,8}(?:BYPASS|SKIP|DISABLE)_(?:AUTH|LOGIN|SECURITY|VERIFY|TLS|SSL)\w{0,24}[ \t]{1,8}(?:1|true)\b|\bif[ \t]{0,8}\([ \t]{0,8}(?:BYPASS|SKIP|DISABLE)_(?:AUTH|LOGIN|SECURITY|VERIFY)\w{0,24}[ \t]{0,8}\)/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const embSecretToSerial: RuleDefinition = {
  ruleId: 'VG-EMB-022',
  name: 'Credential printed to serial',
  description:
    'Serial.print/println/printf of a credential-named variable. Serial output is readable by anyone with physical access and often ends up in captured logs.',
  languages: ['c', 'cpp'],
  category: 'logging',
  severity: 'medium',
  defaultConfidence: 'medium',
  cwe: ['CWE-532'],
  tags: ['embedded', 'ai-prone'],
  remediation: {
    why: 'Printing secrets to the UART exposes them to anyone who can attach a serial adapter, and to any log capture in a test rig or field return.',
    how: 'Never print credentials. Log a redacted placeholder or a hash prefix if you must confirm identity.',
  },
  // The `"`-exclusion in the class kills prompt-text FPs (`Serial.println("Enter
  // password:")`) by construction — any literal before the keyword blocks it.
  // Cost: Serial.printf("pw=%s", password) (literal-first) is missed.
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\bSerial\.print(?:ln|f)?[ \t]{0,8}\([^;\n"]{0,120}?\b(?:password|passwd|psk|secret|api_?key|apikey)\b/gi,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const embRemoveBeforeProdComment: RuleDefinition = {
  ruleId: 'VG-EMB-023',
  name: '"Remove before production" reminder comment',
  description:
    'A comment telling a future reader to remove/disable the code before shipping (imperative removal, or Japanese 本番/デバッグ用). Complements VG-QUAL-009 (which catches "placeholder"/"not for production" labels) with the removal-reminder gap the embedded corpus is full of.',
  languages: ['c', 'cpp'],
  category: 'ai-quality',
  severity: 'medium',
  defaultConfidence: 'medium',
  // TWO knobs, both load-bearing (VG-QUAL-009 is the template):
  //  - contextConfidence:'off' — the comment IS the signal, so it must not be
  //    down-ranked for sitting in a comment.
  //  - skipCommentLines OMITTED — the match lives ON a comment-only line, so
  //    skipping comment lines would DELETE it before anything sees it.
  contextConfidence: 'off',
  tags: ['embedded', 'ai-prone'],
  remediation: {
    why: 'The author flagged this code as not-for-shipping and then it shipped. Either the code is a debug/test path that must go, or the comment is stale.',
    how: 'Remove the flagged code (or the reminder) before release; gate genuine debug paths behind a non-release build type.',
  },
  match: (ctx) => [
    ...runRegex(
      ctx.content,
      /(?:\/\/|#|\/\*|\*)[ \t]{0,12}(?:TODO|FIXME|HACK|XXX)?[ \t:]{0,8}(?:remove|delete|strip|disable)[ \t]{1,8}(?:this[ \t]{1,8}){0,1}(?:before|in|for|prior[ \t]{1,8}to)[ \t]{1,8}(?:prod|production|release|shipping|flight|deployment|deploy)\b/gi,
    ),
    // Japanese removal reminders. A comment opener (`//`, `/*`, `*`, `#`) is
    // REQUIRED on the line so the phrase inside a string literal
    // (`printf("本番環境では…")`) does not fire — the rule is about comments.
    ...runRegex(
      ctx.content,
      /(?:\/\/|\/\*|\*|#)[^\n]{0,40}(?:本番|リリース前|出荷前|デバッグ用)[^\n]{0,16}(?:消|削除|外す|無効|残)/g,
    ),
  ] as RuleMatch[],
};

// ---- Family 4: initialization order (category 'ai-quality'). ----------------
//
// Only the DECIDABLE shape is implemented. EMB-030 (digitalWrite before pinMode)
// is DROPPED, not staged: `digitalWrite(pin, LOW); pinMode(pin, OUTPUT);` is the
// documented Arduino GLITCH-FREE init idiom (set the output latch before
// switching the pin to output), which is lexically identical to the "AI forgot
// the order" bug — so per 17e's rule ("if it FPs, do not detect"), it is left
// out and listed in the README. Cross-function/cross-file init order, power
// sequencing, and hard-coded SD paths are likewise out of scope (dataflow /
// policy, not lexical).

/** Receivers whose methods cannot be called before the receiver's begin(). */
const INIT_RECEIVERS: Array<{ begin: RegExp; use: RegExp }> = [
  { begin: /\bSerial\.begin[ \t]{0,8}\(/, use: /\bSerial\.(?:print(?:ln|f)?|read|write|available)[ \t]{0,8}\(/g },
  { begin: /\bSD\.begin[ \t]{0,8}\(/, use: /\bSD\.(?:open|exists|mkdir|remove)[ \t]{0,8}\(/g },
  { begin: /\bWire\.begin[ \t]{0,8}\(/, use: /\bWire\.(?:beginTransmission|requestFrom|read|write)[ \t]{0,8}\(/g },
  { begin: /\bSPI\.begin[ \t]{0,8}\(/, use: /\bSPI\.transfer[ \t]{0,8}\(/g },
];

export const embUseBeforeBegin: RuleDefinition = {
  ruleId: 'VG-EMB-031',
  name: 'Peripheral used before begin() in setup()',
  description:
    'A Serial/SD/Wire/SPI method is called BEFORE that peripheral\'s begin() within the same setup() body. Provably wrong order (the begin exists later in the same body) — not a maybe-uninitialized guess.',
  languages: ['c', 'cpp'],
  category: 'ai-quality',
  severity: 'low',
  defaultConfidence: 'low',
  cwe: ['CWE-665'],
  tags: ['embedded', 'arduino', 'ai-prone'],
  remediation: {
    why: 'Calling a peripheral before begin() reads/writes an uninitialized interface — the output is silently dropped or garbage until begin() runs.',
    how: 'Move the begin() call above the first use in setup().',
    exampleFix: 'void setup() { Serial.begin(115200); Serial.println("ready"); }',
  },
  match: (ctx) => {
    const raw =
      ctx.content.length > REGEX_INPUT_CAP ? ctx.content.slice(0, REGEX_INPUT_CAP) : ctx.content;
    const scanText = blankCommentsAndStrings(raw);
    const head = /\bvoid[ \t]{1,8}setup[ \t]{0,8}\([ \t]{0,8}\)/g.exec(scanText);
    if (!head) return [];
    const block = extractBlockAfter(scanText, head.index + head[0].length);
    if (!block) return [];
    const out: RuleMatch[] = [];
    for (const r of INIT_RECEIVERS) {
      const bm = r.begin.exec(block.body);
      // No begin() in THIS body → the begin may live in a helper or another
      // file; that is undecidable here, so stay silent.
      if (!bm) continue;
      r.use.lastIndex = 0;
      let um: RegExpExecArray | null;
      while ((um = r.use.exec(block.body)) !== null) {
        if (um.index < bm.index) {
          const pos = indexToPosition(scanText, block.start + um.index);
          out.push({
            startLine: pos.line,
            endLine: pos.line,
            startColumn: pos.column,
            endColumn: pos.column + um[0].length,
            evidence: um[0].trim(),
          });
        }
      }
    }
    return out;
  },
};

export const embeddedAiRules: RuleDefinition[] = [
  embWifiCredential,
  embNamedSecretLiteral,
  embStaticBlePasskey,
  embCleartextHttp,
  embTlsVerificationDisabled,
  embBleJustWorks,
  embDebugDefineOn,
  embAuthBypassFlag,
  embSecretToSerial,
  embRemoveBeforeProdComment,
  embUseBeforeBegin,
];
