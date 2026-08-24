// vibeguard:disable-file VG-INJ-001 reason="the SQL-concatenation string is the `snippet` of a synthetic ORDINARY finding — the control this suite contrasts a protection claim against — and is never executed"
// WP-B2 — the claim ledger on the two surfaces the editor's user actually reads.
//
// A handful of rules report a PROTECTION rather than a vulnerability: the code
// declares an authorization check, or a secret wipe, in a form a build step can
// delete. This extension has one file and no build output, so it cannot tell
// whether the protection survived. Making that ignorance visible instead of
// silent is the behaviour pinned below.
//
// ── WHY BOTH DIRECTIONS ARE ASSERTED ────────────────────────────────────────
//
// The likely defect here is vacuity, not breakage. A suite that only checks
// "the claim shows up when a claim-bearing rule fired" passes identically
// against a producer that stamps `protectionClaims: []` onto every single
// export — and an empty array is a different statement from an absent key: it
// says a ledger was built and came back empty, which this producer has no
// standing to say. The same trap applies to the tree, where a provider that
// marked EVERY row would satisfy any one-sided check. So each behaviour is
// pinned from both sides.
//
// Nothing here asserts a green state, because there is none to assert: every
// claim this process can build is NOT_OBSERVED by construction.
import { describe, expect, it, vi } from 'vitest';
import { toSarif } from '@vibeguard/sarif-adapter';
import { claimsFromFindings, summariseClaims, type Finding } from '@vibeguard/findings-schema';

// Hoisted above every import in this module by Vitest, which is what makes the
// pattern work: `findings-tree.ts` constructs ThemeIcons at module scope, so
// the stand-ins have to exist before it is evaluated.
vi.mock('vscode', () => {
  class EventEmitter<T> {
    private handlers: ((e: T) => void)[] = [];
    event = (h: (e: T) => void): { dispose(): void } => {
      this.handlers.push(h);
      return { dispose: () => undefined };
    };
    fire(e: T): void {
      for (const h of this.handlers) h(e);
    }
    dispose(): void {
      this.handlers = [];
    }
  }
  class ThemeColor {
    constructor(public readonly id: string) {}
  }
  class ThemeIcon {
    constructor(
      public readonly id: string,
      public readonly color?: ThemeColor,
    ) {}
  }
  class TreeItem {
    description?: string;
    tooltip?: string;
    iconPath?: unknown;
    contextValue?: string;
    command?: unknown;
    constructor(
      public readonly label: unknown,
      public readonly collapsibleState?: number,
    ) {}
  }
  class Range {
    constructor(
      public startLine: number,
      public startCol: number,
      public endLine: number,
      public endCol: number,
    ) {}
  }
  return {
    EventEmitter,
    ThemeColor,
    ThemeIcon,
    TreeItem,
    Range,
    TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
    Uri: {
      parse: (s: string) => ({ toString: () => s, fsPath: s.replace(/^file:\/\//, '') }),
    },
    window: {},
    workspace: {},
  };
});

import { buildExportResponse, type ExportInputs } from './export.js';
import { FindingsTreeProvider } from './findings-tree.js';
import { claimTooltipLines } from './status-bar.js';

const BASE: Omit<Finding, 'findingId' | 'ruleId' | 'title' | 'description' | 'category'> = {
  severity: 'high',
  confidence: 'medium',
  language: 'typescript',
  filePath: 'src/routes/admin.ts',
  startLine: 42,
  sourceEngine: 'core-rule',
};

/**
 * A finding from a claim-bearing rule.
 *
 * The dangerous shape is carried as a string literal on purpose: the rule that
 * produces it blanks string contents before matching, so this fixture cannot
 * make the repository's own scan of its test files report a fresh VG-AUTH-009.
 */
const CLAIMED: Finding = {
  ...BASE,
  findingId: 'finding-claimed',
  ruleId: 'VG-AUTH-009',
  title: 'Access control that only runs in development',
  description: 'An authorization check placed inside a development-mode conditional.',
  category: 'auth',
  snippet: "if (devMode) { if (!session.isOwner) throw new Error('forbidden'); }",
};

/** An ordinary finding: reports a hazard, declares no protection. */
const ORDINARY: Finding = {
  ...BASE,
  findingId: 'finding-ordinary',
  ruleId: 'VG-INJ-001',
  title: 'SQL built by string concatenation',
  description: 'User input is concatenated into a SQL statement.',
  category: 'injection',
  severity: 'critical',
  snippet: 'db.query("SELECT * FROM users WHERE id = " + id)',
};

const inputs = (findings: Finding[]): ExportInputs => ({
  findings,
  degradations: [],
  suppressions: [],
  declaredPackageVetoes: [],
  declaredPackageVetoRan: false,
  generatedAt: '2026-08-24T00:00:00.000Z',
});

describe('buildExportResponse carries the claim ledger', () => {
  it('attaches an unsettled claim for a claim-bearing finding', () => {
    const response = buildExportResponse(inputs([CLAIMED, ORDINARY]));
    expect(response.protectionClaims).toBeDefined();
    const claims = response.protectionClaims ?? [];
    // One claim, from the one claim-bearing rule — not one per finding.
    expect(claims).toHaveLength(1);
    expect(claims[0]?.claimant).toBe('VG-AUTH-009');
    expect(claims[0]?.claimantLayer).toBe('source');
    expect(claims[0]?.filePath).toBe('src/routes/admin.ts');
    expect(claims[0]?.startLine).toBe(42);
  });

  it('leaves every exported claim NOT_OBSERVED, with nothing that could have settled it', () => {
    const response = buildExportResponse(inputs([CLAIMED]));
    const claims = response.protectionClaims ?? [];
    expect(claims.length).toBeGreaterThan(0);
    for (const c of claims) {
      expect(c.state).toBe('NOT_OBSERVED');
      // `crossExaminedAt` names the layer whose observation moved the claim.
      // Nothing in this process observes an artefact, so its presence would
      // mean the editor had settled its own claim — the one transition this
      // whole channel exists to forbid.
      expect(c).not.toHaveProperty('crossExaminedAt');
      expect(c).not.toHaveProperty('note');
      expect(c.history).toBeUndefined();
    }
  });

  it('omits the key entirely when nothing declared a protection', () => {
    const response = buildExportResponse(inputs([ORDINARY]));
    // Not `toEqual([])` and not `toBeUndefined()`: the assertion is about the
    // KEY. An absent key says "no finding declared a protection"; `[]` would
    // say "a ledger was built and came back empty", which is a statement about
    // a mechanism that does not exist on this side.
    expect(Object.prototype.hasOwnProperty.call(response, 'protectionClaims')).toBe(false);
    expect(JSON.stringify(response)).not.toContain('protectionClaims');
  });

  it('reaches the SARIF document as an unchecked claim, not a result', () => {
    // The SARIF adapter already renders these; what was missing is that the
    // editor never put them on the response, so the rendering had nothing to
    // render. Asserting through `toSarif` is what tests the wiring rather than
    // the field assignment.
    const sarif = toSarif(buildExportResponse(inputs([CLAIMED])), { toolVersion: '0.0.0' });
    const notifications = sarif.runs[0]?.invocations?.[0]?.toolExecutionNotifications ?? [];
    const claimNotes = notifications.filter((n) => n.message.text.includes('VG-AUTH-009'));
    expect(claimNotes.length).toBeGreaterThan(0);
    expect(claimNotes[0]?.level).toBe('note');
    expect(claimNotes[0]?.message.text).toContain('NOT checked against the shipped bytes');
    expect(claimNotes[0]?.message.text).toContain('This is a claim, not a result.');
  });

  it('says nothing reassuring about the claim in the exported document', () => {
    const response = buildExportResponse(inputs([CLAIMED]));
    const rendered = JSON.stringify(response.protectionClaims);
    for (const word of ['PRESENT', 'verified', 'safe', 'all good']) {
      expect(rendered).not.toContain(word);
    }
  });
});

describe('FindingsTreeProvider marks the rows that declare a protection', () => {
  /** The provider only ever reads these two members off the runner. */
  const fakeRunner = (findings: Finding[]): any => ({
    onDidChangeFindings: () => ({ dispose: () => undefined }),
    getAllFindings: () => new Map([['file:///w/src/routes/admin.ts', findings]]),
  });

  const rowFor = (finding: Finding): any => {
    const provider = new FindingsTreeProvider(fakeRunner([finding]));
    const [file] = provider.getChildren();
    expect(file).toBeDefined();
    const [row] = provider.getChildren(file!);
    expect(row).toBeDefined();
    return provider.getTreeItem(row!);
  };

  it('suffixes the description and explains the gap in the tooltip', () => {
    const item = rowFor(CLAIMED);
    expect(item.description).toBe('VG-AUTH-009 · line 42 · declared protection, UNVERIFIED');
    expect(item.tooltip).toContain('a build step can remove');
    expect(item.tooltip).toContain('This editor cannot see your build output');
    expect(item.tooltip).toContain('UNVERIFIED');
    // The one actionable thing, named exactly as the status bar names it, so a
    // reader who saw it there types the same command here.
    expect(item.tooltip).toContain('vibeguard <dir> --after-build <your dist directory>');
    // The finding's own description survives; the claim is added to it.
    expect(item.tooltip).toContain(CLAIMED.description);
  });

  it('names the declared subject rather than leaving the reader to guess', () => {
    expect(rowFor(CLAIMED).tooltip).toContain(
      'an authorization check that only runs in development',
    );
  });

  it('leaves an ordinary finding unmarked', () => {
    const item = rowFor(ORDINARY);
    expect(item.description).toBe('VG-INJ-001 · line 42');
    expect(item.tooltip).not.toContain('UNVERIFIED');
    expect(item.tooltip).not.toContain('--after-build');
    expect(item.tooltip).not.toContain('declared protection');
  });

  it('offers no green, verified or tick affordance on the marked row', () => {
    const item = rowFor(CLAIMED);
    const surface = `${String(item.description)}\n${String(item.tooltip)}`;
    for (const word of ['verified', 'safe', 'all good', 'no issues']) {
      expect(surface).not.toContain(word);
    }
    // A claim must never recolour the row: severity still owns the icon.
    expect(item.iconPath?.color?.id).toBe('vibeguard.critical');
  });
});

describe('the status bar says the count the same way every other surface does', () => {
  it('takes the summary verbatim from summariseClaims().line', () => {
    const lines = claimTooltipLines([CLAIMED, ORDINARY]);
    const expected = summariseClaims(claimsFromFindings([CLAIMED, ORDINARY])).line;
    // The identity, not a substring match. This is the whole point of the
    // change: the moment somebody composes a second phrasing of this count
    // here, the browser panel and the status bar start disagreeing about the
    // same ledger and this goes red.
    expect(lines).toContain(expected);
  });

  it('says nothing at all when no finding declares a protection', () => {
    // Vacuity in the other direction: silence must mean "nothing declared a
    // protection", never "the declared protections are fine".
    expect(claimTooltipLines([ORDINARY])).toEqual([]);
  });

  it('names the gap and the command that closes it, and reassures about nothing', () => {
    const surface = claimTooltipLines([CLAIMED]).join(' ');
    expect(surface).toContain('UNVERIFIED');
    expect(surface).toContain('--after-build');
    for (const word of ['verified present', 'safe', 'all good', 'no issues', '✓']) {
      expect(surface).not.toContain(word);
    }
  });
});
