// vibeguard:disable-file VG-INJ-010 VG-INJ-011 VG-INJ-012 VG-CRYPTO-003
// This file defines Java-specific rules; the literal patterns
// (`Runtime.getRuntime().exec(`, `DocumentBuilderFactory.newInstance`,
// `ObjectInputStream`) appear inside regex sources and remediation
// prose by design. The XXE remediation also embeds the literal Apache
// XML feature URI `http://apache.org/...` which trips VG-CRYPTO-003.
import type { RuleDefinition } from '../rule-types.js';
import { runRegex } from '../matcher-utils.js';

export const javaRuntimeExecConcat: RuleDefinition = {
  ruleId: 'VG-INJ-010',
  name: 'Runtime.exec / ProcessBuilder with string concatenation',
  description:
    'Runtime.getRuntime().exec(...) or new ProcessBuilder(...) built from string concatenation. The string is parsed by the OS shell loader and any interpolated variable can break out into a separate command.',
  languages: ['java'],
  category: 'injection',
  severity: 'critical',
  defaultConfidence: 'medium',
  cwe: ['CWE-78'],
  owasp: ['A03:2021'],
  tags: ['command-injection', 'ai-prone'],
  remediation: {
    why: 'A concatenated command string lets an attacker who controls any segment add their own arguments — or, on Windows, run a separate process via & / |.',
    how: 'Pass arguments as a String[] (or List<String>) to exec / ProcessBuilder so each value is one argv slot. Validate the program path against an allowlist.',
    exampleFix: 'new ProcessBuilder("git", "log", commitId).start();',
  },
  match: (ctx) => [
    ...runRegex(
      ctx.content,
      /\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\([^)]*\+\s*[\w$]/g,
      { skipCommentLines: true, language: ctx.language },
    ),
    ...runRegex(
      ctx.content,
      /\bnew\s+ProcessBuilder\s*\([^)]*\+\s*[\w$]/g,
      { skipCommentLines: true, language: ctx.language },
    ),
  ],
};

export const javaXxeDocumentBuilder: RuleDefinition = {
  ruleId: 'VG-INJ-011',
  name: 'XML parser configured without disabling external entities (XXE)',
  description:
    'DocumentBuilderFactory / SAXParserFactory / XMLInputFactory is used without explicitly disabling DTD processing and external entities. The defaults are unsafe in most JDKs.',
  languages: ['java'],
  category: 'injection',
  severity: 'high',
  defaultConfidence: 'low',
  cwe: ['CWE-611'],
  tags: ['xxe', 'ai-prone'],
  remediation: {
    why: 'A default XML parser resolves external entities, letting attacker-controlled XML read local files (file:///etc/passwd) and trigger SSRF via http:// entities.',
    how: 'Call setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) on the factory, or use the OWASP-recommended configuration for your parser. Reject XML where DTD is not required.',
    exampleFix: 'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(\s*\)\s*;/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const javaObjectInputStream: RuleDefinition = {
  ruleId: 'VG-INJ-012',
  name: 'ObjectInputStream.readObject on untrusted input',
  description:
    'Java native deserialization via ObjectInputStream / readObject reconstructs arbitrary class graphs and is a well-known remote-code-execution vector when the source bytes are attacker-controlled.',
  languages: ['java'],
  category: 'injection',
  severity: 'critical',
  defaultConfidence: 'medium',
  cwe: ['CWE-502'],
  tags: ['deserialization', 'ai-prone'],
  remediation: {
    why: 'readObject instantiates whatever classes are in the byte stream and runs their gadgets during construction. Long history of public CVEs (Commons-Collections, Spring, Hibernate, etc.) prove this is exploitable in practice.',
    how: 'Use a data format with a fixed schema (JSON via Jackson with default typing OFF, Protobuf, Avro). If native serialization is unavoidable, wrap the stream with a look-ahead ObjectInputStream that rejects classes outside an allowlist.',
  },
  match: (ctx) => [
    ...runRegex(
      ctx.content,
      /\bnew\s+ObjectInputStream\s*\(/g,
      { skipCommentLines: true, language: ctx.language },
    ),
    ...runRegex(
      ctx.content,
      /\.readObject\s*\(\s*\)/g,
      { skipCommentLines: true, language: ctx.language },
    ),
  ],
};

export const javaRules: RuleDefinition[] = [
  javaRuntimeExecConcat,
  javaXxeDocumentBuilder,
  javaObjectInputStream,
];
