import * as vscode from 'vscode';
import type { Finding } from '@vibeguard/findings-schema';
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
  critical: new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground')),
  high: new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground')),
  medium: new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground')),
  low: new vscode.ThemeIcon('info'),
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
    item.description = `${f.ruleId} · line ${line}`;
    item.tooltip = f.description;
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
