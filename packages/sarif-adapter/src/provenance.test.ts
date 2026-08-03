// Tests for the AI-authorship provenance collector.
//
// The negative cases are the point of this file and outnumber the positives on
// purpose. A missed marker degrades to "nothing was declared", which the claim
// limit already says means nothing; a WRONG marker asserts something false about
// a named tool and about a person, inside an artifact that gets uploaded to a
// security dashboard. So each negative below names the real-world text it is
// standing in for.
import { describe, expect, it } from 'vitest';
import {
  AI_PROVENANCE_CLAIM_LIMIT,
  collectAiProvenance,
  parseGitLogRecords,
  type AiAuthorshipMarker,
} from './provenance.js';

/** Build the exact blob `git log -z --format=%H%n%B` produces. */
const gitLogBlob = (...messages: string[]): string =>
  messages.map((m, i) => `${String(i).padStart(40, 'a')}\n${m}`).join('\0') + '\0';

const markersOf = (...messages: string[]): AiAuthorshipMarker[] =>
  collectAiProvenance({ gitLog: gitLogBlob(...messages) }).observedAuthorshipMarkers;

describe('git trailer markers', () => {
  it("reads Claude's own trailer form", () => {
    const m = markersOf('fix: thing\n\nCo-Authored-By: Claude <noreply@anthropic.com>');
    expect(m).toEqual([
      {
        channel: 'git-trailer',
        readFrom: 'git-log',
        field: 'co-authored-by',
        assistant: 'claude',
        matchedOn: 'email-address',
        occurrences: 1,
      },
    ]);
  });

  // This repository's own commits carry a decorated display name. The address is
  // what identifies the tool, so the name being unrecognisable must not matter.
  it('matches on the address when the display name is decorated', () => {
    const m = markersOf('x\n\nCo-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>');
    expect(m[0]?.assistant).toBe('claude');
    expect(m[0]?.matchedOn).toBe('email-address');
  });

  it("reads GitHub's account-id-prefixed noreply form", () => {
    const m = markersOf('x\n\nCo-authored-by: Copilot <198982749+Copilot@users.noreply.github.com>');
    expect(m[0]?.assistant).toBe('copilot');
    expect(m[0]?.matchedOn).toBe('email-address');
  });

  it('reads a bracketed bot local-part', () => {
    const m = markersOf(
      'x\n\nCo-authored-by: Devin AI <devin-ai-integration[bot]@users.noreply.github.com>',
    );
    expect(m[0]?.assistant).toBe('devin');
    expect(m[0]?.matchedOn).toBe('email-address');
  });

  it('records a display-name-only match as the weaker evidence it is', () => {
    const m = markersOf('x\n\nCo-authored-by: Cursor Agent <someone@corp.example>');
    expect(m[0]?.assistant).toBe('cursor');
    expect(m[0]?.matchedOn).toBe('display-name');
  });

  it('treats an AI-declaring trailer key as a declaration even with no tool named', () => {
    const m = markersOf('x\n\nAI-Assisted-By: an unnamed internal tool');
    expect(m).toEqual([
      {
        channel: 'git-trailer',
        readFrom: 'git-log',
        field: 'ai-assisted-by',
        assistant: null,
        matchedOn: 'declaration-only',
        occurrences: 1,
      },
    ]);
  });

  it('upgrades a declaring key to a named assistant when the value names one', () => {
    const m = markersOf('x\n\nAI-Generated-By: Cursor Agent <cursoragent@cursor.com>');
    expect(m[0]?.assistant).toBe('cursor');
    expect(m[0]?.matchedOn).toBe('email-address');
  });
});

/**
 * ★ THE FALSE-POSITIVE SET.
 *
 * Every entry here is text that exists in real repositories and that a substring
 * implementation reports as AI authorship.
 */
describe('negative conditions', () => {
  it('does not flag human co-authors whose names contain an assistant name', () => {
    expect(
      markersOf(
        'x\n\n' +
          'Co-authored-by: Jean-Claude Dupont <jc@corp.example>\n' +
          'Co-authored-by: Marcus Cursor <marcus@corp.example>\n' +
          'Co-authored-by: Copilot Systems Ltd <billing@copilot-systems.example>\n' +
          'Co-authored-by: Gemini Ravi Devin <grd@corp.example>',
      ),
    ).toEqual([]);
  });

  it('does not flag prose that talks about an assistant', () => {
    expect(
      markersOf(
        'refactor: rework the Claude integration\n\n' +
          'This was co-authored by Claude in spirit only. See the Copilot docs for\n' +
          'why Cursor and Codex disagree here.',
      ),
    ).toEqual([]);
  });

  it('does not flag a trailer that is quoted rather than declared', () => {
    // A `git revert`, a squash body, or a pasted commit. The trailer belongs to
    // a different commit; counting it duplicates one declaration into two.
    expect(
      markersOf(
        'revert: undo the parser change\n\n' +
          'This reverts commit deadbeef, whose message was:\n' +
          '    Co-authored-by: Claude <noreply@anthropic.com>\n' +
          '> Co-authored-by: Claude <noreply@anthropic.com>',
      ),
    ).toEqual([]);
  });

  it('does not flag a trailer inside a fenced code block', () => {
    expect(
      markersOf(
        'docs: explain our trailer convention\n\n' +
          'Write it like this:\n' +
          '```\n' +
          'Co-authored-by: Claude <noreply@anthropic.com>\n' +
          '```\n',
      ),
    ).toEqual([]);
  });

  it('does not accept whitespace before the trailer colon', () => {
    expect(markersOf('x\n\nCo-authored-by : Claude <noreply@anthropic.com>')).toEqual([]);
  });

  // The refused form, pinned so nobody re-adds it. `[AI]` and `feat(ai):` mean
  // "the AI subsystem" in any repository that builds one — which is most of the
  // corpus this tool is swept over.
  it('does not read a bare [AI] or (ai) scope as an authorship declaration', () => {
    expect(markersOf('[AI] tune the ranking prompt')).toEqual([]);
    expect(markersOf('feat(ai): add a model selector')).toEqual([]);
    expect(markersOf('ai: retry on 429')).toEqual([]);
  });

  it('does not flag a Generated-with footer naming a non-assistant tool', () => {
    expect(markersOf('x\n\nGenerated with protoc 3.21.1')).toEqual([]);
    expect(markersOf('x\n\nGenerated with [Docker BuildKit](https://docs.docker.com)')).toEqual([]);
  });

  it('does not flag an identity trailer key whose value names nobody registered', () => {
    expect(markersOf('x\n\nCo-authored-by: Alice <alice@corp.example>')).toEqual([]);
    expect(markersOf('x\n\nGenerated-by: openapi-generator 7.0.0')).toEqual([]);
  });

  // ★ The correction that removed `claude`, `devin` and `jules` from the display
  // -name table. All three are human given names; Claude is one of the most
  // common male given names in France. The address is what identifies the tool,
  // and over this repository's own history every Claude trailer matched on it.
  it('does not flag a person whose given name is an assistant name', () => {
    expect(markersOf('x\n\nCo-authored-by: Claude <claude@corp.example>')).toEqual([]);
    expect(markersOf('x\n\nCo-authored-by: Devin <devin@corp.example>')).toEqual([]);
    expect(markersOf('x\n\nCo-authored-by: Jules <jules@corp.example>')).toEqual([]);
  });

  it('does not flag a corporate address that merely shares an assistant vendor domain', () => {
    // Registering `anthropic.com` or `openai.com` wholesale would make every
    // employee commit an AI-authorship marker. Only the machine addresses count.
    expect(markersOf('x\n\nCo-authored-by: A Person <a.person@anthropic.com>')).toEqual([]);
    expect(markersOf('x\n\nCo-authored-by: B Person <b.person@openai.com>')).toEqual([]);
  });
});

describe('commit message footers and subject declarations', () => {
  it('reads the generated-with footer through its emoji decoration', () => {
    const m = markersOf('x\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)');
    expect(m).toEqual([
      {
        channel: 'commit-message-footer',
        readFrom: 'git-log',
        field: 'generated with',
        assistant: 'claude',
        matchedOn: 'display-name',
        occurrences: 1,
      },
    ]);
  });

  it('reads an unbracketed generated-with label', () => {
    expect(markersOf('x\n\nGenerated with Cursor Agent')[0]?.assistant).toBe('cursor');
  });

  it('reads an unambiguous subject declaration', () => {
    const m = markersOf('AI-generated: add the CSV exporter');
    expect(m).toEqual([
      {
        channel: 'commit-subject-declaration',
        readFrom: 'git-log',
        field: 'ai-generated',
        assistant: null,
        matchedOn: 'declaration-only',
        occurrences: 1,
      },
    ]);
    expect(markersOf('[AI-assisted] add the CSV exporter')[0]?.field).toBe('ai-assisted');
  });

  it('reads a declaration only at the subject, not deep in the body', () => {
    expect(markersOf('fix: thing\n\nAI-generated: is how we would have tagged it')).toEqual([]);
  });

  // The subject comes from the raw message, not from the filtered line list:
  // otherwise an over-long subject is dropped by the line filter and the next
  // surviving line is silently promoted into subject position.
  it('does not promote a body line into subject position behind an over-long subject', () => {
    expect(
      markersOf(`fix: ${'x'.repeat(600)}\nAI-generated: is how we would have tagged it`),
    ).toEqual([]);
  });
});

describe('PR body channel', () => {
  const body = [
    '## Summary',
    '',
    'Adds the exporter.',
    '',
    '## AI assistance',
    '',
    '- [x] Claude Code',
    '- [ ] Copilot',
    '- some prose mentioning Cursor',
    '',
    '## Testing',
    '',
    '- Gemini',
  ].join('\n');

  const collect = (): AiAuthorshipMarker[] =>
    collectAiProvenance({ prBody: body }).observedAuthorshipMarkers;

  it('records the designated section itself as a declaration', () => {
    expect(collect()).toContainEqual({
      channel: 'pr-body-section',
      readFrom: 'pr-body',
      field: 'ai assistance',
      assistant: null,
      matchedOn: 'declaration-only',
      occurrences: 1,
    });
  });

  it('reads a ticked assistant out of the designated section', () => {
    expect(collect().filter((m) => m.assistant === 'claude')).toHaveLength(1);
  });

  it('does not read an UNTICKED box as a declaration', () => {
    // An unfilled PR template would otherwise declare every assistant it lists.
    expect(collect().some((m) => m.assistant === 'copilot')).toBe(false);
  });

  it('does not read an assistant name out of prose inside the section', () => {
    expect(collect().some((m) => m.assistant === 'cursor')).toBe(false);
  });

  it('does not read a list item in a different section', () => {
    expect(collect().some((m) => m.assistant === 'gemini')).toBe(false);
  });

  it('ignores a heading that is not in the designated set', () => {
    // `AI usage` describes a product, not a patch — the same ambiguity that got
    // the `[AI]` subject prefix refused.
    const m = collectAiProvenance({
      prBody: '## AI usage\n\n- [x] Claude\n',
    }).observedAuthorshipMarkers;
    expect(m).toEqual([]);
  });

  it('reads a trailer out of a PR body and labels its source', () => {
    const m = collectAiProvenance({
      prBody: 'Body text.\n\nCo-authored-by: Claude <noreply@anthropic.com>\n',
      prBodyLabel: 'pr-body',
    }).observedAuthorshipMarkers;
    expect(m[0]?.channel).toBe('pr-body-trailer');
    expect(m[0]?.readFrom).toBe('pr-body');
  });
});

describe('aggregation and the inspection window', () => {
  it('counts distinct commits, not raw hits', () => {
    const twoCommits = markersOf(
      'a\n\nCo-authored-by: Claude <noreply@anthropic.com>',
      'b\n\nCo-authored-by: Claude <noreply@anthropic.com>',
    );
    expect(twoCommits[0]?.occurrences).toBe(2);

    const oneCommitTwice = markersOf(
      'a\n\nCo-authored-by: Claude <noreply@anthropic.com>\nCo-authored-by: Claude <noreply@anthropic.com>',
    );
    expect(oneCommitTwice[0]?.occurrences).toBe(1);
  });

  it('reports which channels were read, and distinguishes unread from empty', () => {
    const neither = collectAiProvenance({});
    expect(neither.inspected.channelsRead).toEqual([]);
    expect(neither.inspected.commitsInspected).toBe(0);

    const emptyLog = collectAiProvenance({ gitLog: '' });
    expect(emptyLog.inspected.channelsRead).toEqual(['git-log']);
    expect(emptyLog.inspected.commitsInspected).toBe(0);
  });

  it('reports a truncated window rather than silently capping', () => {
    const many = Array.from({ length: 2100 }, (_, i) => `commit ${i}`);
    const o = collectAiProvenance({ gitLog: gitLogBlob(...many) });
    expect(o.inspected.commitWindowTruncated).toBe(true);
    expect(o.inspected.commitsInspected).toBe(2000);
  });

  it('carries the claim limit into the observation', () => {
    expect(collectAiProvenance({}).claimLimit).toBe(AI_PROVENANCE_CLAIM_LIMIT);
    expect(AI_PROVENANCE_CLAIM_LIMIT).toMatch(/must not be used as a denominator/);
  });

  // Nothing here may report a rate, a score, or a boolean verdict. If a field
  // with one of these names ever appears, the reading this whole module refuses
  // has become expressible.
  it('exposes no field that could be read as a verdict or a rate', () => {
    const json = JSON.stringify(
      collectAiProvenance({ gitLog: gitLogBlob('x\n\nCo-authored-by: Claude <noreply@anthropic.com>') }),
    );
    for (const forbidden of ['aiAuthored', 'aiGenerated', 'risk', 'score', 'rate', 'percent', 'ratio']) {
      expect(json.includes(`"${forbidden}`)).toBe(false);
    }
  });
});

describe('determinism', () => {
  const messages = [
    'a\n\nCo-authored-by: Claude <noreply@anthropic.com>',
    'b\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)',
    'c\n\nCo-authored-by: Copilot <198982749+Copilot@users.noreply.github.com>',
    'AI-assisted: d',
  ];

  it('is byte-identical across runs', () => {
    const a = JSON.stringify(collectAiProvenance({ gitLog: gitLogBlob(...messages) }));
    const b = JSON.stringify(collectAiProvenance({ gitLog: gitLogBlob(...messages) }));
    expect(a).toBe(b);
  });

  it('does not depend on commit order', () => {
    const forward = markersOf(...messages);
    const reversed = markersOf(...[...messages].reverse());
    // Occurrences are per-commit and identical either way; only ordering could differ.
    expect(JSON.stringify(forward)).toBe(JSON.stringify(reversed));
  });
});

describe('bounded work on hostile input', () => {
  it('parses NUL-separated records and refuses a forged boundary', () => {
    // NUL is the one byte a commit message cannot hold, so a message that tries
    // to look like two commits cannot.
    const { records } = parseGitLogRecords(gitLogBlob('a\n\nbody with\nnewlines'));
    expect(records).toHaveLength(1);
    expect(records[0]?.message).toBe('a\n\nbody with\nnewlines');
  });

  // The A1 shape: whitespace runs adjacent to another quantifier. Every regex in
  // the module is bounded, so a crafted line is linear work. This asserts the
  // outcome rather than the shape, because the shape is easy to reintroduce.
  it('stays fast on pathological lines', () => {
    const nasty = [
      `Co-authored-by:${' '.repeat(20000)}<${'a'.repeat(20000)}@x>`,
      `${'#'.repeat(5000)} ${'x'.repeat(5000)}`,
      `${'-'.repeat(20000)}`,
      `Generated with ${' '.repeat(20000)}[${'x'.repeat(20000)}]`,
    ].join('\n');
    const started = Date.now();
    collectAiProvenance({ gitLog: gitLogBlob(nasty), prBody: nasty });
    expect(Date.now() - started).toBeLessThan(1000);
  });
});
