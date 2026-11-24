#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vg_wipe_hook -- Claude Code の PostToolUse（matcher: Write|Edit）hook。書かれた .c の消去処理が -O2 で削除されていないかを確かめる。

標準入力：Claude Code の hook の入力（JSON）。使うのは tool_name・tool_input.file_path（Write・Edit とも絶対パス）・cwd。
処理    ：.c でなければ何もしない（終了コード 0）。.c なら，まず Windows 側で消去処理の文を探し（コンパイルしない），
          在れば WSL の clang-18 と gcc-13 で -O2 にコンパイルして確かめる（wipe_core.py を WSL の python3 で走らせる）。
          Linux（WSL の中）で動かしたときは wipe_core を直接呼ぶ。
終了コード（Claude Code の約束：PostToolUse の 2 は「標準エラーを Claude に見せる。道具は既に走った」）
  0  .c でない／消去処理が無い／全ての消去処理が両コンパイラで残った
  2  消去処理が削除された（どの関数の何行目か，と削除されない書き方の例を標準エラーに 2 行）
  2  コンパイルできない・判定できない（黙って 0 を返さない。理由を標準エラーに 2 行。コードの誤りか環境の誤りかを分けて書く）
環境変数（任意）
  VG_WSL_DISTRO（既定 Ubuntu-24.04）  VG_WSL_USER（既定 root）  VG_HOOK_TIMEOUT（秒，既定 100）
  VG_HOOK_LOG    1 回ごとの記録（JSON Lines）を足すファイル
  VG_HOOK_CCS    コンパイラ（既定 clang-18,gcc-13）
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import wipe_core  # noqa: E402  （scan だけを Windows 側で使う。標準ライブラリだけで動く）

DISTRO = os.environ.get('VG_WSL_DISTRO', 'Ubuntu-24.04')
WSL_USER = os.environ.get('VG_WSL_USER', 'root')
TIMEOUT = int(os.environ.get('VG_HOOK_TIMEOUT', '100'))
CCS = os.environ.get('VG_HOOK_CCS', 'clang-18,gcc-13')
TOOLS = ('Write', 'Edit', 'MultiEdit')


def emit(lines, code, log):
    msg = '\n'.join(lines) + '\n' if lines else ''
    if msg:
        sys.stderr.buffer.write(msg.encode('utf-8'))
        sys.stderr.flush()
    log['exit'] = code
    log['stderr'] = lines
    lp = os.environ.get('VG_HOOK_LOG')
    if lp:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(lp)), exist_ok=True)
            with open(lp, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log, ensure_ascii=False) + '\n')
        except OSError:
            pass
    return code


def to_wsl(p):
    p = os.path.abspath(p)
    if os.name != 'nt':
        return p
    return '/mnt/' + p[0].lower() + p[2:].replace('\\', '/')


def shown_name(path, cwd):
    """標準エラーに出す名前：作業フォルダの下なら相対パス，外ならファイル名だけ（研究のフォルダのパスを出さない）"""
    try:
        if cwd:
            rel = os.path.relpath(path, cwd)
            if not rel.startswith('..'):
                return rel.replace('\\', '/')
    except ValueError:
        pass
    return os.path.basename(path)


def split_args(s):
    out, d, cur = [], 0, ''
    for ch in s:
        if ch in '([{':
            d += 1
        elif ch in ')]}':
            d -= 1
        if ch == ',' and d == 0:
            out.append(cur.strip())
            cur = ''
        else:
            cur += ch
    out.append(cur.strip())
    return out


def fix_example(text):
    """消去処理の文から，削除されない書き方の例を作る（標準エラーの 2 行目にそのまま入る文）"""
    m = re.match(r'^(memset|bzero)\s*\((.*)\)\s*;', text)
    if m:
        a = split_args(m.group(2))
        if m.group(1) == 'memset' and len(a) >= 3:
            return f'`explicit_bzero({a[0]}, {a[2]});`'
        if m.group(1) == 'bzero' and len(a) >= 2:
            return f'`explicit_bzero({a[0]}, {a[1]});`'
    if text.startswith(('for', 'while', 'do')):
        return '`explicit_bzero(buf, n);`，または volatile unsigned char * を通して 1 バイトずつ 0 を書くループ'
    m = re.match(r'^([A-Za-z_]\w*)\s*\(', text)
    if m:
        return f'{m.group(1)} の中の `memset(p, 0, n);` を `explicit_bzero(p, n);` にする'
    return '`explicit_bzero(buf, n);`'


ENV_REASONS = ('NOT_INSTALLED', 'TIMEOUT')


def decode_err(b):
    """wsl.exe 自身の誤りは UTF-16 で来ることがある"""
    if b.count(b'\x00') > len(b) // 4:
        return b.decode('utf-16-le', errors='replace')
    return b.decode('utf-8', errors='replace')


def run_core(path):
    core = os.path.join(HERE, 'wipe_core.py')
    if os.name == 'nt':
        cmd = ['wsl.exe', '-d', DISTRO, '-u', WSL_USER, '--exec', 'python3', to_wsl(core), '--json', '--cc', CCS, to_wsl(path)]
    else:
        cmd = [sys.executable, core, '--json', '--cc', CCS, path]
    r = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT)
    out = r.stdout.decode('utf-8', errors='replace').strip().split('\n')
    try:
        return json.loads(out[-1]), r
    except (ValueError, IndexError):
        # wsl.exe 自身の誤り（配布が無いなど）は標準出力に UTF-16 で来る（2026-11-05 に確かめた）
        err = [l.strip() for l in (decode_err(r.stderr) + '\n' + decode_err(r.stdout)).replace('\x00', '').split('\n') if l.strip()]
        raise RuntimeError(f'WSL での確認が結果を返さなかった（終了コード {r.returncode}：{(err[0] if err else "")[:120]}）')


def main():
    t0 = time.time()
    log = {'t': time.strftime('%Y-%m-%dT%H:%M:%S'), 'hook': 'vg_wipe_hook', 'v': 1}
    try:
        raw = sys.stdin.buffer.read().decode('utf-8', errors='replace')
        ev = json.loads(raw)
    except Exception as e:  # noqa: BLE001
        return emit(['VibeGuard: hook の入力（JSON）を読めず，消去処理を確かめられなかった（' + e.__class__.__name__ + '）。',
                     'コードの誤りではない。-O2 で消去処理が残るかは確かめられていない。'], 2, log)
    tool = ev.get('tool_name')
    ti = ev.get('tool_input') or {}
    path = ti.get('file_path') or (ev.get('tool_response') or {}).get('filePath')
    log.update(tool=tool, session=ev.get('session_id'), tool_use_id=ev.get('tool_use_id'), path=path)
    if tool not in TOOLS:
        log['result'] = 'SKIP_TOOL'
        return emit([], 0, log)
    if not path or not str(path).endswith('.c'):
        log['result'] = 'SKIP_NOT_C'
        return emit([], 0, log)
    name = shown_name(path, ev.get('cwd'))
    if not os.path.isfile(path):
        log['result'] = 'NO_FILE'
        return emit([f'VibeGuard: {name} が見つからず，消去処理を確かめられなかった。',
                     '-O2 で消去処理が残るかは確かめられていない。'], 2, log)
    try:
        src = open(path, encoding='utf-8', errors='replace').read()
        cands = wipe_core.scan(src)
    except Exception as e:  # noqa: BLE001
        log['result'] = 'SCAN_ERROR'
        return emit([f'VibeGuard: {name} の消去処理を探す途中で失敗し，確かめられなかった（{e.__class__.__name__}）。',
                     'コードの誤りとは限らない。-O2 で消去処理が残るかは確かめられていない。'], 2, log)
    if not cands:
        log['result'] = 'NO_WIPE'
        log['ms'] = int((time.time() - t0) * 1000)
        return emit([], 0, log)
    try:
        res, proc = run_core(path)
    except subprocess.TimeoutExpired:
        log['result'] = 'TIMEOUT'
        return emit([f'VibeGuard: {name} の確認が {TIMEOUT} 秒で終わらず，消去処理を確かめられなかった。',
                     'コードの誤りとは限らない。-O2 で消去処理が残るかは確かめられていない。'], 2, log)
    except Exception as e:  # noqa: BLE001
        log['result'] = 'RUN_ERROR'
        log['error'] = str(e)[:300]
        return emit([f'VibeGuard: {name} の消去処理を確かめる道具を実行できなかった（{str(e)[:160]}）。',
                     'コードの誤りではない。-O2 で消去処理が残るかは確かめられていない。'], 2, log)
    v = res.get('verdict')
    log['result'] = v
    log['core'] = res
    log['ms'] = int((time.time() - t0) * 1000)
    if v in ('SURVIVED', 'NO_WIPE'):
        return emit([], 0, log)
    if v == 'ELIMINATED':
        items, fixes = [], []
        for c in res.get('functions', []):
            by_line = {}
            for cc, pc in (c.get('per_cc') or {}).items():
                for ln in pc.get('deleted') or []:
                    by_line.setdefault(ln, []).append(cc)
            for ln in sorted(by_line):
                text = next((w['text'] for w in c['wipes'] if w['line'] == ln), '')
                items.append(f"関数 {c['fn']} の {ln} 行目 `{text}`（{'・'.join(by_line[ln])}）")
                fixes.append(fix_example(text))
        head = '；'.join(items[:3]) + (f'；ほか {len(items) - 3} 件' if len(items) > 3 else '')
        fx = fixes[0] if fixes else '`explicit_bzero(buf, n);`'
        return emit([f'VibeGuard: {name} の消去処理が -O2 の最適化で削除された：{head}。',
                     f'削除されない書き方の例：{fx}（#include <string.h>，glibc 2.25 以降）。直して保存すると，この確認がもう一度走る。'], 2, log)
    if v == 'COMPILE_ERROR':
        errs = res.get('compile_errors') or {}
        ccs = '・'.join(errs) or CCS
        first = next(iter(errs.values()), '')
        return emit([f'VibeGuard: {name} を {ccs} の -O2 でコンパイルできず，消去処理が残るかを確かめられなかった（{first[:160]}）。',
                     '使う関数の宣言（プロトタイプ）や #include の不足を直すと確かめられる。'], 2, log)
    reason = res.get('reason') or v
    if any(k in reason for k in ENV_REASONS):
        return emit([f'VibeGuard: {name} の消去処理を確かめる環境が整っておらず，確かめられなかった（{reason[:160]}）。',
                     'コードの誤りではない。-O2 で消去処理が残るかは確かめられていない。'], 2, log)
    return emit([f'VibeGuard: {name} の消去処理が -O2 で残るかを確かめられなかった（{reason[:160]}）。',
                 'コードの誤りとは限らない。消去処理を explicit_bzero で書くと確かめられる。'], 2, log)


if __name__ == '__main__':
    sys.exit(main())
