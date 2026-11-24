#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wipe_core -- C のファイルの消去処理が -O2 の最適化で削除されていないかを，clang-18 と gcc-13 で確かめる（hook の中身。WSL で動く）。

    python3 wipe_core.py --json FILE.c [--cc clang-18,gcc-13] [--opt -O2]

やり方（check_wipe.py を流用。関数の名前を知らなくてよいように，ファイルの全ての関数を見る）
  1. ファイルの直下の関数ごとに，消去処理の文を探す（check_wipe.find_spans。/* wipe */ の印，無ければ memset(…, 0, …)・explicit_bzero・
     bzero・memset_s・消去の補助関数の呼び出し・volatile の関数ポインタ・volatile の書き込みでゼロにするループ）。
     どの関数にも無ければ NO_WIPE で終わる（コンパイルしない）。
  2. 元のファイル（w）と，その関数の消去処理の文を全て抜いた版（wo）を，同じ設定でアセンブリにする。
     設定は VibeGuard の測定（ablation-cell.mjs）と同じ：-S -std=gnu11 -w -Wno-error=implicit-function-declaration -fcf-protection=none -O2。
     両方の末尾に，必ず残る memset を持つ対照の関数（vgctl_control。ablation-cell.mjs の CONTROL と同じ）を足す。
  3. 2 つの読みで決める。
       差分判定：対象の関数の命令列（ラベルの番号を伏せたもの）が w と wo で同じ → ELIMINATED（削除された）
       命令列の読み：w にだけ在る行に，ゼロを書く命令（memset 系の呼び出し・rep stos・即値 0 の書き込み・ゼロにしたレジスタの書き込み）か
                     呼び出し（消去の補助関数・volatile の関数ポインタ）が在るか（asm_read2.mjs の写しに呼び出しを足した）
       差分が在るのに命令列の読みが 0 → DISAGREE（判定できない。gcc でレジスタの割り当てだけが変わった例が在る）
  4. 消去処理の文が 2 つ以上で，全てを抜いた比較が「残った」なら，1 つずつ抜いて比べる（r6b で足した読み）。
     1 つを抜いても命令列が同じ文は，その文が削除された（PARTIAL）。
  5. 対照の関数の memset が命令列に無ければ，読みが働いていない（CONTROL_MISSING。判定できない）。

ファイルの判定（強い順）：ELIMINATED（どこかの関数で削除が在る。PARTIAL を含む）＞ COMPILE_ERROR ＞ UNDECIDED ＞ SURVIVED ＞ NO_WIPE
終了コード：0 SURVIVED・NO_WIPE／1 ELIMINATED／2 COMPILE_ERROR／3 UNDECIDED
「残った」は命令列の上で削除されなかったという意味で，秘密データがメモリに残らないことの保証ではない。
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_wipe as cw  # noqa: E402

FLAGS = ['-S', '-std=gnu11', '-w', '-Wno-error=implicit-function-declaration', '-fcf-protection=none']
CONTROL = '''
void vgctl_fill(unsigned char *p, unsigned long n);
void vgctl_use(const unsigned char *p, unsigned long n);
void vgctl_control(void) {
  unsigned char vgctl_secret[32];
  vgctl_fill(vgctl_secret, sizeof vgctl_secret);
  vgctl_use(vgctl_secret, sizeof vgctl_secret);
  __builtin_memset(vgctl_secret, 0, sizeof vgctl_secret);
  vgctl_use(vgctl_secret, sizeof vgctl_secret);
}
'''
CCS = ['clang-18', 'gcc-13']
TIMEOUT = 60

# ---- 命令列の読み（asm_read2.mjs の写し。行は check_wipe.body_of で整えたもの） ----
ZCALL = re.compile(r'^(?:call|callq|jmp|jmpq)\s+\*?(?:__)?(?:memset|memset_chk|explicit_bzero|explicit_bzero_chk|bzero|memset_s|explicit_memset)(?:@PLT)?\b')
ANYCALL = re.compile(r'^(?:call|callq)\s+\S+|^(?:jmp|jmpq)\s+\*')
REP = re.compile(r'^rep(?:\s+|;)stos[bwlq]?\b')
IMM = re.compile(r'^mov[bwlq]?\s+\$0,\s*[^,]*\(%[a-z0-9]+')
VSTORE = re.compile(r'^v?mov(?:aps|ups|apd|upd|dqa|dqu|dqa64|dqu64|dqa32|dqu32|q|d)\s+%([xyz]mm\d+),\s*[^,]*\(%[a-z0-9]+')
VZERO = re.compile(r'^v?(?:pxor|xorps|xorpd|pxord|pxorq)\s+%([xyz]mm\d+),\s*(?:%\1,\s*)?%\1\s*$')
GSTORE = re.compile(r'^mov[bwlq]?\s+%([a-z0-9]+),\s*[^,]*\(%[a-z0-9]+')
GZERO = re.compile(r'^xor[lq]?\s+%([a-z0-9]+),\s*%\1\s*$')
FAMILY = {'eax': 'a', 'rax': 'a', 'ax': 'a', 'al': 'a', 'ebx': 'b', 'rbx': 'b', 'bx': 'b', 'bl': 'b', 'ecx': 'c', 'rcx': 'c',
          'cx': 'c', 'cl': 'c', 'edx': 'd', 'rdx': 'd', 'dx': 'd', 'dl': 'd', 'esi': 'si', 'rsi': 'si', 'sil': 'si',
          'edi': 'di', 'rdi': 'di', 'dil': 'di', 'ebp': 'bp', 'rbp': 'bp'}


def fam(r):
    return FAMILY.get(r, re.sub(r'^(r\d+)[dwb]?$', r'\1', r))


def only_in_w(bw, bwo):
    count = {}
    for l in bwo:
        count[l] = count.get(l, 0) + 1
    only = []
    for l in bw:
        c = count.get(l, 0)
        if c > 0:
            count[l] = c - 1
        else:
            only.append(l)
    return only


def zero_read(bw, bwo):
    """w にだけ在る行のうち，ゼロを書く命令と呼び出しの数"""
    only = only_in_w(bw, bwo) if bwo is not None else list(bw)
    vz, gz = set(), set()
    for l in bw:
        m = VZERO.match(l)
        if m:
            vz.add('x' + m.group(1)[1:] if m.group(1)[0] in 'yz' else m.group(1))
        m = GZERO.match(l)
        if m:
            gz.add(fam(m.group(1)))
    n = {'call': 0, 'rep': 0, 'imm': 0, 'vec': 0, 'gpr': 0, 'otherCall': 0}
    for l in only:
        if ZCALL.match(l):
            n['call'] += 1
        elif REP.match(l):
            n['rep'] += 1
        elif IMM.match(l):
            n['imm'] += 1
        else:
            m = VSTORE.match(l)
            if m and ('x' + m.group(1)[1:] if m.group(1)[0] in 'yz' else m.group(1)) in vz:
                n['vec'] += 1
                continue
            m = GSTORE.match(l)
            if m and fam(m.group(1)) in gz:
                n['gpr'] += 1
            elif ANYCALL.match(l):
                n['otherCall'] += 1
    n['zero'] = n['call'] + n['rep'] + n['imm'] + n['vec'] + n['gpr']
    n['onlyLines'] = len(only)
    return n


# ---- ソースを読む ----
def line_of(src, pos):
    return src.count('\n', 0, pos) + 1


def is_static(m, brace):
    k = max(m.rfind(';', 0, brace), m.rfind('}', 0, brace)) + 1
    return re.search(r'\bstatic\b', m[k:brace]) is not None


def scan(src):
    """消去処理の文を持つ関数の一覧（コンパイルしない）"""
    m = cw.mask(src)
    fns = cw.functions(m)
    out = []
    for name, (a, b) in fns.items():
        if name.startswith('vgctl_'):
            continue
        spans, how = cw.find_spans(src, name)
        if spans:
            out.append({'fn': name, 'static': is_static(m, a), 'how': how, 'spans': spans,
                        'wipes': [{'line': line_of(src, s), 'text': ' '.join(src[s:e].split())[:100]} for s, e in spans]})
    return out


# ---- コンパイル ----
def compile_asm(cc, text, tmp, tag, opt, inc=()):
    p = os.path.join(tmp, f'{tag}.c')
    o = os.path.join(tmp, f'{tag}.s')
    with open(p, 'w', encoding='utf-8') as f:
        f.write(text)
    try:
        r = subprocess.run([cc] + FLAGS + list(inc) + [opt, '-o', o, p], capture_output=True, text=True, timeout=TIMEOUT)
    except FileNotFoundError:
        return None, 'NOT_INSTALLED'
    except subprocess.TimeoutExpired:
        return None, f'TIMEOUT {TIMEOUT}s'
    if r.returncode != 0 or not os.path.exists(o):
        errs = [l for l in r.stderr.split('\n') if 'error' in l] or r.stderr.strip().split('\n')
        return None, (errs[0] if errs else f'exit {r.returncode}').replace(p, '<file>')[:200]
    with open(o, encoding='utf-8', errors='replace') as f:
        return f.read(), None


def preprocess(cc, text, tmp, tag, opt, inc=()):
    """前処理だけの出力（行の印なし）。失敗したら None"""
    p = os.path.join(tmp, f'{tag}.c')
    with open(p, 'w', encoding='utf-8') as f:
        f.write(text)
    try:
        r = subprocess.run([cc, '-E', '-P', '-std=gnu11', '-w'] + list(inc) + [opt, p], capture_output=True, text=True, timeout=TIMEOUT)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def shared_evidence(bw, c):
    """w の本体に，消去の関数の呼び出し・間接の呼び出し・消去の補助関数の呼び出し・ゼロを書く命令（即値 0・rep stos・ゼロのベクタ）が在るか"""
    helpers = {re.match(r'^([A-Za-z_]\w*)\s*\(', w['text']).group(1) for w in c['wipes'] if re.match(r'^([A-Za-z_]\w*)\s*\(', w['text'])}
    for l in bw:
        if ZCALL.match(l) or re.match(r'^(?:call|callq|jmp|jmpq)\s+\*', l):
            return True
        m = re.match(r'^(?:call|callq|jmp|jmpq)\s+([A-Za-z_]\w*)', l)
        if m and m.group(1) in helpers:
            return True
    z = zero_read(bw, None)
    return z['imm'] + z['rep'] + z['vec'] > 0


def control_present(asm):
    b = cw.body_of(asm, 'vgctl_control')
    return bool(b) and zero_read(b, None)['zero'] > 0


def check(path, ccs=None, opt='-O2'):
    t0 = time.time()
    ccs = ccs or CCS
    src = open(path, encoding='utf-8', errors='replace').read()
    # 写しを一時フォルダでコンパイルするので，元のファイルのフォルダを -I で足す（#include "x.h" のため。2026-11-05 の変更履歴）
    inc = ['-I', os.path.dirname(os.path.abspath(path))]
    res = {'schema': 'wipe-core-v1', 'file': os.path.basename(path), 'opt': opt, 'ccs': ccs, 'flags': FLAGS,
           'compilers': {}, 'functions': [], 'verdict': None}
    try:
        cands = scan(src)
    except Exception as e:  # noqa: BLE001
        res.update(verdict='UNDECIDED', reason=f'ソースを読めない（{e.__class__.__name__}）')
        return res
    if not cands:
        res['verdict'] = 'NO_WIPE'
        res['ms'] = int((time.time() - t0) * 1000)
        return res
    tmp = tempfile.mkdtemp(prefix='wipecore_')
    try:
        for c in cands:
            c['per_cc'] = {}
        for cc in ccs:
            info = {}
            res['compilers'][cc] = info
            if not shutil.which(cc):
                info['error'] = 'NOT_INSTALLED'
                continue
            aw, err = compile_asm(cc, src + CONTROL, tmp, f'{cc}-w', opt, inc)
            if aw is None:
                info['error'] = err
                continue
            info['control'] = control_present(aw)
            pp_w = []   # 前処理の出力（必要になったときだけ作る）

            def active(sp):
                """その文が前処理の後に残っているか（#ifdef の外れた所の文を「削除」と読まないため。2026-11-05 の変更履歴）"""
                if not pp_w:
                    pp_w.append(preprocess(cc, src, tmp, f'{cc}-ppw', opt, inc))
                p1 = preprocess(cc, cw.ablate(src, [sp]), tmp, f'{cc}-ppa', opt, inc)
                return pp_w[0] is None or p1 is None or pp_w[0] != p1

            for c in cands:
                pc = {}
                c['per_cc'][cc] = pc
                if not info['control']:
                    pc['status'] = 'CONTROL_MISSING'
                    continue
                fn = c['fn']
                bw = cw.body_of(aw, fn)
                awo, err2 = compile_asm(cc, cw.ablate(src, c['spans']) + CONTROL, tmp, f'{cc}-wo', opt, inc)
                if awo is None:
                    pc['status'] = 'ABLATION_ERROR'
                    pc['error'] = err2
                    continue
                bwo = cw.body_of(awo, fn)
                if c['static'] and (bw is None or bwo is None):
                    # static の関数は，インライン展開で単独の本体が在ったり無かったりする。消去処理は呼び出し側の関数で確かめる
                    pc['status'] = 'NOT_EMITTED'
                    continue
                if bw is None or bwo is None:
                    pc['status'] = 'NOT_IN_ASM'
                    continue
                if bw == bwo:
                    act = [k for k, sp in enumerate(c['spans']) if active(sp)]
                    if not act:
                        pc['status'] = 'INACTIVE'
                        continue
                    pc['status'] = 'ELIMINATED'
                    pc['deleted'] = [c['wipes'][k]['line'] for k in act]
                    continue
                z = zero_read(bw, bwo)
                pc['zero'] = z
                only_ev = z['zero'] + z['otherCall'] > 0
                dels = []
                if len(c['spans']) >= 2:
                    # 1 つずつ抜いて比べる（r6b の読み）。1 つを抜いても命令列が同じ文は削除された
                    for k, sp in enumerate(c['spans']):
                        a1, e1 = compile_asm(cc, cw.ablate(src, [sp]) + CONTROL, tmp, f'{cc}-wo{k}', opt, inc)
                        if a1 is not None and cw.body_of(a1, fn) == bw and active(sp):
                            dels.append(c['wipes'][k]['line'])
                    pc['oneByOne'] = len(c['spans'])
                if dels:
                    pc['status'] = 'PARTIAL'
                    pc['deleted'] = dels
                elif only_ev:
                    pc['status'] = 'SURVIVED'
                elif shared_evidence(bw, c):
                    # 差分は在るが，w にだけ在る行に消去の命令が無い：抜かなかった別の経路の消去と末尾が併合された形（2026-11-05 の変更履歴）。
                    # w の本体に消去の関数の呼び出しかゼロを書く命令が在れば，残ったと読む
                    pc['status'] = 'SURVIVED'
                    pc['how'] = 'shared'
                else:
                    pc['status'] = 'DISAGREE'
        # ファイルの判定
        sts = [pc.get('status') for c in cands for pc in c['per_cc'].values()]
        errs = {cc: i['error'] for cc, i in res['compilers'].items() if i.get('error')}
        OK = ('SURVIVED', 'NOT_EMITTED', 'INACTIVE')
        if any(s in ('ELIMINATED', 'PARTIAL') for s in sts):
            res['verdict'] = 'ELIMINATED'
        elif errs and all(e not in ('NOT_INSTALLED',) and not e.startswith('TIMEOUT') for e in errs.values()):
            res['verdict'] = 'COMPILE_ERROR'
        elif errs or any(s not in OK for s in sts):
            res['verdict'] = 'UNDECIDED'
            bad = sorted({s for s in sts if s not in OK} | set(errs.values()))
            res['reason'] = ', '.join(str(b) for b in bad)
        elif not any(s == 'SURVIVED' for s in sts):
            res['verdict'] = 'NO_WIPE'
            res['reason'] = '消去処理は，呼ばれない static の関数か，前処理で外れた所にだけ在る'
        else:
            res['verdict'] = 'SURVIVED'
        if errs:
            res['compile_errors'] = errs
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for c in cands:
        c.pop('spans', None)
    res['functions'] = cands
    res['ms'] = int((time.time() - t0) * 1000)
    return res


EXIT = {'SURVIVED': 0, 'NO_WIPE': 0, 'ELIMINATED': 1, 'COMPILE_ERROR': 2, 'UNDECIDED': 3}


def main():
    ap = argparse.ArgumentParser(description='消去処理が -O2 で削除されていないかを確かめる（ファイルの全ての関数）')
    ap.add_argument('file')
    ap.add_argument('--cc', default=','.join(CCS))
    ap.add_argument('--opt', default='-O2')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()
    try:
        res = check(a.file, [c for c in a.cc.split(',') if c], a.opt)
    except Exception as e:  # noqa: BLE001
        res = {'schema': 'wipe-core-v1', 'file': os.path.basename(a.file), 'verdict': 'UNDECIDED',
               'reason': f'内部の誤り（{e.__class__.__name__}: {str(e)[:120]}）'}
    res['exit'] = EXIT[res['verdict']]
    if a.json:
        sys.stdout.write(json.dumps(res, ensure_ascii=True) + '\n')
    else:
        print(json.dumps(res, ensure_ascii=False, indent=1))
    sys.exit(res['exit'])


if __name__ == '__main__':
    main()
