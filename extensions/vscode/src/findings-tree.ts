import * as vscode from 'vscode';
import { CLAIM_BEARING_RULES, type Finding } from '@vibeguard/findings-schema';
import type { ScanRunner } from './runner.js';

type Node = FileNode | FindingNode;

class FileNode {
  readonly kind = 'file' as const;
  constructor(
    readonly uri: vscode.Uri,
    readonly findings: Finding[],
  ) {}
}

class FindingNode {
  readonly kind = 'finding' as const;
  constructor(
    readonly uri: vscode.Uri,
    readonly finding: Finding,
  ) {}
}

const SEVERITY_ICON: Record<string, vscode.ThemeIcon> = {
  critical: new vscode.ThemeIcon('error', new vscode.ThemeColor('vibeguard.critical')),
  high: new vscode.ThemeIcon('error', new vscode.ThemeColor('vibeguard.critical')),
  medium: new vscode.ThemeIcon('warning', new vscode.ThemeColor('vibeguard.issue')),
  low: new vscode.ThemeIcon('info', new vscode.ThemeColor('vibeguard.issue')),
  info: new vscode.ThemeIcon('info'),
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function worstSeverity(findings: Finding[]): string {
  let worst = 'info';
  let bestRank = SEVERITY_RANK.info ?? 4;
  for (const f of findings) {
    const r = SEVERITY_RANK[f.severity] ?? 4;
    if (r < bestRank) {
      bestRank = r;
      worst = f.severity;
    }
  }
  return worst;
}

export class FindingsTreeProvider implements vscode.TreeDataProvider<Node> {
  private readonly emitter = new vscode.EventEmitter<Node | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;

  constructor(private readonly runner: ScanRunner) {
    runner.onDidChangeFindings(() => this.emitter.fire(undefined));
  }

  getTreeItem(node: Node): vscode.TreeItem {
    if (node.kind === 'file') {
      const item = new vscode.TreeItem(
        node.uri,
        vscode.TreeItemCollapsibleState.Expanded,
      );
      const worst = worstSeverity(node.findings);
      item.iconPath = SEVERITY_ICON[worst];
      item.description = `${node.findings.length} finding${node.findings.length === 1 ? '' : 's'}`;
      item.contextValue = 'vibeguard.fileNode';
      return item;
    }
    const f = node.finding;
    const line = f.startLine ?? 1;
    const item = new vscode.TreeItem(
      `${f.severity.toUpperCase()} · ${f.title}`,
      vscode.TreeItemCollapsibleState.None,
    );
    // ── THE LEDGER, ON THE ROW THE USER CLICKS ──────────────────────────────
    //
    // A handful of rules do not report "you wrote something dangerous" but "you
    // wrote a protection in a form a build step removes". Left unmarked, such a
    // row reads as an ordinary issue and the reader has no way to know that the
    // interesting question — did the protection survive the build? — was never
    // asked. This extension has one file and no build output, so it cannot ask
    // it; what it can do is refuse to let the silence pass for an answer.
    //
    // The mark only ever ADDS something to check. There is no green state, no
    // tick, and no "verified" affordance here, because there is nothing this
    // process could observe that would earn one: a claim built in the editor is
    // NOT_OBSERVED by construction. The wording is the status bar's, kept
    // deliberately identical so the two surfaces cannot drift into two
    // phrasings of the same fact.
    const claim = CLAIM_BEARING_RULES[f.ruleId];
    item.description = `${f.ruleId} · line ${line}${claim ? ' · declared protection, UNVERIFIED' : ''}`;
    // The row's description is already full (`ruleId · line N`), so confidence
    // rides on the tooltip instead of competing for that space.
    const detail = f.confidence ? `${f.description}\n\nConfidence: ${f.confidence}` : f.description;
    item.tooltip = claim
      ? [
          detail,
          '',
          `This finding declares a protection — ${claim.subject} — that a build step can remove.`,
          'This editor cannot see your build output, so it is UNVERIFIED here.',
          'Run: vibeguard <dir> --after-build <your dist directory>',
        ].join('\n')
      : detail;
    item.iconPath = SEVERITY_ICON[f.severity];
    item.contextValue = 'vibeguard.findingNode';
    item.command = {
      command: 'vscode.open',
      title: 'Open',
      arguments: [
        node.uri,
        {
          selection: new vscode.Range(
            Math.max(0, line - 1),
            Math.max(0, (f.startColumn ?? 1) - 1),
            Math.max(0, (f.endLine ?? line) - 1),
            Math.max(0, (f.endColumn ?? (f.startColumn ?? 1) + 1) - 1),
          ),
        } as vscode.TextDocumentShowOptions,
      ],
    };
    return item;
  }

  getChildren(node?: Node): Node[] {
    if (!node) {
      // Root: one entry per file that has any findings.
      const entries: FileNode[] = [];
      for (const [uriString, findings] of this.runner.getAllFindings()) {
        if (findings.length === 0) continue;
        entries.push(new FileNode(vscode.Uri.parse(uriString), findings));
      }
      entries.sort((a, b) => {
        const aw = SEVERITY_RANK[worstSeverity(a.findings)] ?? 4;
        const bw = SEVERITY_RANK[worstSeverity(b.findings)] ?? 4;
        if (aw !== bw) return aw - bw;
        return a.uri.fsPath.localeCompare(b.uri.fsPath);
      });
      return entries;
    }
    if (node.kind === 'file') {
      const sorted = [...node.findings].sort((a, b) => {
        const ar = SEVERITY_RANK[a.severity] ?? 4;
        const br = SEVERITY_RANK[b.severity] ?? 4;
        if (ar !== br) return ar - br;
        return (a.startLine ?? 0) - (b.startLine ?? 0);
      });
      return sorted.map((f) => new FindingNode(node.uri, f));
    }
    return [];
  }
}
