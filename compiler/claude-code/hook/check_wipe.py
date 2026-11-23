#!/usr/bin/env python3
"""check_wipe.py -- C の関数の消去処理が，最適化の後の命令列に残っているかを確かめる（secret-wipe-c skill の確認）。

    python3 check_wipe.py FILE.c FUNC [--cc gcc,clang] [--opt -O2] [--cflags "-D_FORTIFY_SOURCE=2"] [--json]

やり方（VibeGuard Compiler の「検出」を，リポジトリなしで動くように単純にしたもの）
  1. 対象の関数の中の消去処理の文を探す。`/* wipe */` の印が付いた文があれば，それだけを使う。
     無ければ，ゼロで埋める memset・explicit_bzero・bzero・memset_s などの呼び出し，それらを中で呼ぶ補助関数の呼び出し，
     volatile な関数ポインタを通した呼び出し，volatile な書き込みでゼロにするループを，消去処理とみなす。
  2. 消去処理の文を除いた版を作り，元の版と同じ設定でアセンブリにする。
  3. 対象の関数の命令列（ラベルの番号を伏せたもの）を比べる。同じなら，消去処理は最適化で削除されている。
終了コード：0 全てのコンパイラで残った／1 どれかで削除された／2 消去処理が見つからない・コンパイルできない・関数が無い。
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

WIPE_FN = ('explicit_bzero', 'bzero', 'memset_s', 'memset', 'SecureZeroMemory', 'RtlSecureZeroMemory',
           'OPENSSL_cleanse', 'sodium_memzero', 'explicit_memset', 'memzero_explicit')
CALL_RE = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
MARK_RE = re.compile(r'/\*\s*wipe\s*\*/')
ZERO_ARG = re.compile(r"^\s*(0|0x0+|'\\0'|\(\s*\w+\s*\)\s*0|0[uUlL]*)\s*$")


def mask(src):
    """コメントと文字列・文字の中身を空白にする（長さと改行は変えない）"""
    out, i, n = list(src), 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith('//', i):
            j = src.find('\n', i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = ' '
            i = j
        elif src.startswith('/*', i):
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != '\n':
                    out[k] = ' '
            i = j
        elif c in '"\'':
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == chr(92) else 1
            for k in range(i + 1, min(j, n)):
                if out[k] != '\n':
                    out[k] = ' '
            i = j + 1
        elif c == '#' and (i == 0 or src[src.rfind('\n', 0, i) + 1:i].strip() == ''):
            # 前処理の行（続き行も）は，文の区切りの判断から外すため空白にする。中身は前処理器が読む
            j = i
            while True:
                e = src.find('\n', j)
                e = n if e < 0 else e
                if e > 0 and src[e - 1] == chr(92) and e < n:
                    j = e + 1
                    continue
                break
            for k in range(i, e):
                if out[k] != '\n':
                    out[k] = ' '
            i = e
        else:
            i += 1
    return ''.join(out)


def match_paren(s, i):
    """s[i] == '(' か '{' に対応する閉じ括弧の位置"""
    o = s[i]
    c = ')' if o == '(' else '}'
    d = 0
    for j in range(i, len(s)):
        if s[j] == o:
            d += 1
        elif s[j] == c:
            d -= 1
            if d == 0:
                return j
    return -1


def functions(m):
    """ファイルの直下で定義された関数：{名前: (本体の { の位置, } の位置)}"""
    out, depth, i = {}, 0, 0
    while i < len(m):
        ch = m[i]
        if ch == '{':
            if depth == 0:
                # 直前の ) と，その前の名前
                k = i - 1
                while k >= 0 and m[k].isspace():
                    k -= 1
                if k >= 0 and m[k] == ')':
                    # 対応する ( を探す
                    d, p = 0, k
                    while p >= 0:
                        if m[p] == ')':
                            d += 1
                        elif m[p] == '(':
                            d -= 1
                            if d == 0:
                                break
                        p -= 1
                    q = p - 1
                    while q >= 0 and m[q].isspace():
                        q -= 1
                    e = q + 1
                    while q >= 0 and (m[q].isalnum() or m[q] == '_'):
                        q -= 1
                    name = m[q + 1:e]
                    if name and name not in ('if', 'for', 'while', 'switch', 'return', 'sizeof'):
                        end = match_paren(m, i)
                        if end > 0:
                            out[name] = (i, end)
                            i = end + 1
                            continue
            depth += 1
        elif ch == '}':
            depth -= 1
        i += 1
    return out


LABEL_RE = re.compile(r'(?:case\b[^:;{}]*|default|[A-Za-z_]\w*)\s*:(?!:)\s*')


def stmt_start(m, pos, lo):
    """pos を含む文の始まり（直前の ; { } の次。前に付いたラベル out: や case 1: は文に含めない）"""
    k = pos - 1
    while k > lo and m[k] not in ';{}':
        k -= 1
    k += 1
    while k < pos and m[k].isspace():
        k += 1
    while True:
        mm = LABEL_RE.match(m, k)
        if not mm or mm.end() > pos or m[k:mm.end()].strip().startswith(('else', 'return')):
            break
        k = mm.end()
    return k


def stmt_end(m, pos):
    """pos から始まる文の終わり（; を含む。for/while/do はその本体まで）"""
    w = re.match(r'(for|while|do)\b', m[pos:])
    if w:
        k = pos + len(w.group(1))
        if w.group(1) != 'do':
            while m[k].isspace():
                k += 1
            k = match_paren(m, k) + 1
        while m[k].isspace():
            k += 1
        if m[k] == '{':
            e = match_paren(m, k) + 1
        else:
            e = m.find(';', k) + 1
        if w.group(1) == 'do':
            e = m.find(';', e) + 1
        return e
    d = 0
    for j in range(pos, len(m)):
        if m[j] in '({[':
            d += 1
        elif m[j] in ')}]':
            d -= 1
        elif m[j] == ';' and d == 0:
            return j + 1
    return -1


def args_of(m, open_paren):
    close = match_paren(m, open_paren)
    inner, out, d, cur = m[open_paren + 1:close], [], 0, ''
    for ch in inner:
        if ch in '([{':
            d += 1
        elif ch in ')]}':
            d -= 1
        if ch == ',' and d == 0:
            out.append(cur)
            cur = ''
        else:
            cur += ch
    out.append(cur)
    return out


def zero_call(m, name, open_paren):
    a = args_of(m, open_paren)
    if name == 'memset':
        return len(a) >= 3 and bool(ZERO_ARG.match(a[1]))
    if name == 'memset_s':
        return len(a) >= 4 and bool(ZERO_ARG.match(a[2]))
    return True


def volatile_fnptrs(m):
    """ファイルの中の，memset などを入れた volatile な関数ポインタの名前"""
    names = set()
    for mm in re.finditer(r'volatile[^;{}]*?\(\s*\*\s*(?:const\s+)?(?:volatile\s+)?([A-Za-z_]\w*)\s*\)[^;{}]*=\s*&?\s*(\w+)\s*;', m):
        if mm.group(2) in WIPE_FN:
            names.add(mm.group(1))
    for mm in re.finditer(r'\(\s*\*\s*(?:const\s+)?volatile\s+([A-Za-z_]\w*)\s*\)[^;{}]*=\s*&?\s*(\w+)\s*;', m):
        if mm.group(2) in WIPE_FN:
            names.add(mm.group(1))
    return names


def dest_name(m, open_paren):
    """呼び出しの第 1 引数の変数名（&key[0]，(void *)key，ctx->key などから key・ctx を取る）"""
    a = args_of(m, open_paren)
    ids = re.findall(r'[A-Za-z_]\w*', a[0]) if a else []
    ids = [i for i in ids if i not in ('void', 'char', 'unsigned', 'const', 'volatile', 'uint8_t', 'sizeof')]
    return ids[0] if ids else None


def used_between(m, name, a, b, wipe_spans):
    """name が [a, b) で使われるか（消去処理の文の中，asm 文の中，sizeof の中の出現は数えない）"""
    for mm in re.finditer(r'\b' + re.escape(name) + r'\b', m[a:b]):
        p = a + mm.start()
        if any(x <= p < y for x, y in wipe_spans):
            continue
        s = stmt_start(m, p, a)
        if re.match(r'(__asm__|asm|__asm)\b', m[s:]):
            continue
        if re.search(r'\bsizeof\s*\(?\s*$', m[max(a, p - 12):p]):
            continue
        return True
    return False


def wipe_spans_in(m, lo, hi, helpers, vptrs, init_filter=True, sig_lo=None):
    """[lo, hi) の中の消去処理の文の位置。sig_lo は関数の宣言の始まり（引数の volatile も見るため）"""
    spans = []
    body = m[lo if sig_lo is None else sig_lo:hi]
    has_volatile = 'volatile' in body
    cand = []
    for mm in CALL_RE.finditer(m, lo, hi):
        name = mm.group(1)
        op = mm.end() - 1
        is_wipe = (name in WIPE_FN and zero_call(m, name, op)) or name in helpers or name in vptrs
        if not is_wipe:
            continue
        s = stmt_start(m, mm.start(), lo)
        if re.match(r'(if|for|while|return)\b', m[s:]):
            continue
        e = stmt_end(m, s)
        if e > 0:
            cand.append((s, e, dest_name(m, op)))
    # 同じ領域へのゼロ埋めが後にもう一度あり，その間で領域を使っていれば，前の方は初期化（使う前にゼロで埋める）として外す。
    # 同じ領域への最後のゼロ埋めは，必ず消去処理として扱う
    allw = [(a, b) for a, b, _ in cand]
    for k, (s, e, d) in enumerate(cand):
        if init_filter and d:
            later = [(s2, e2) for s2, e2, d2 in cand[k + 1:] if d2 == d]
            if any(used_between(m, d, e, s2, allw) for s2, _ in later):
                continue
        spans.append((s, e))
    if has_volatile:
        for mm in re.finditer(r'\b(for|while|do)\b', m[lo:hi]):
            s = lo + mm.start()
            if any(a <= s < b for a, b in spans):
                continue
            e = stmt_end(m, s)
            if e > 0 and re.search(r'=\s*0\s*;', m[s:e]):
                spans.append((s, e))
    spans.sort()
    merged = []
    for a, b in spans:
        if merged and a < merged[-1][1]:
            continue
        merged.append((a, b))
    return merged


def find_spans(src, fn):
    m = mask(src)
    fns = functions(m)
    if fn not in fns:
        return None, 'FUNC_NOT_FOUND'
    lo, hi = fns[fn]
    # 印の付いた文
    marked = []
    for mm in MARK_RE.finditer(src):
        p = mm.start()
        if not (lo < p < hi):
            continue
        k = p - 1
        while k > lo and m[k].isspace():
            k -= 1
        if m[k] not in ';}':
            continue
        s = stmt_start(m, k if m[k] == ';' else k, lo)
        # } で終わる文（ループ）は，対応する { の前の for/while から
        if m[k] == '}':
            d, q = 0, k
            while q > lo:
                if m[q] == '}':
                    d += 1
                elif m[q] == '{':
                    d -= 1
                    if d == 0:
                        break
                q -= 1
            s = stmt_start(m, q, lo)
            s2 = m.rfind('for', lo, q)
            s3 = m.rfind('while', lo, q)
            s = max(s, 0) if max(s2, s3) < s else max(s2, s3)
        marked.append((s, k + 1))
    if marked:
        return sorted(set(marked)), 'marked'
    vptrs = volatile_fnptrs(m)
    helpers = set()
    for name, (a, b) in fns.items():
        sig = max(m.rfind(';', 0, a), m.rfind('}', 0, a)) + 1   # 宣言の始まり（引数の volatile を見る）
        if name != fn and wipe_spans_in(m, a, b + 1, set(), vptrs, init_filter=False, sig_lo=sig):
            helpers.add(name)
    return wipe_spans_in(m, lo, hi + 1, helpers, vptrs), 'detected'


def ablate(src, spans):
    out = list(src)
    for a, b in spans:
        for k in range(a, b):
            if out[k] != '\n':
                out[k] = ' '
        out[a] = ';'
    return ''.join(out)


NORM = [(re.compile(r'\.LBB\d+_\d+'), '.LBB_'), (re.compile(r'\.L[A-Za-z_]*\d+'), '.L_'), (re.compile(r'\s+'), ' ')]


def body_of(asm, fn):
    lines = asm.split('\n')
    out, on = [], False
    for l in lines:
        if not on:
            if re.match(r'^' + re.escape(fn) + r':', l):
                on = True
            continue
        t = l.split('#', 1)[0].strip()
        if t.startswith('.cfi_endproc') or re.match(r'\.size\s+' + re.escape(fn) + r'\b', t) or re.match(r'\.Lfunc_end', t):
            break
        if not t or (t.startswith('.') and not t.endswith(':')):
            continue
        for rx, rep in NORM:
            t = rx.sub(rep, t)
        out.append(t)
    return out if on else None


def compile_asm(cc, path, opt, cflags):
    r = subprocess.run([cc, '-std=gnu11', '-w', opt] + cflags + ['-S', '-o', '-', path], capture_output=True, text=True)
    return (r.stdout if r.returncode == 0 else None), r.stderr.strip().split('\n')[0][:200]


def check(path, fn, ccs, opt='-O2', cflags=()):
    src = open(path, encoding='utf-8', errors='replace').read()
    spans, how = find_spans(src, fn)
    res = {'file': path, 'function': fn, 'opt': opt, 'cflags': list(cflags), 'wipes': [], 'how': how, 'compilers': {}}
    if spans is None:
        res['result'] = 'FUNC_NOT_FOUND'
        return res, 2
    res['wipes'] = [' '.join(src[a:b].split())[:120] for a, b in spans]
    if not spans:
        res['result'] = 'NO_WIPE_FOUND'
        return res, 2
    tmp = tempfile.mkdtemp(prefix='check_wipe_')
    try:
        w, wo = os.path.join(tmp, 'w.c'), os.path.join(tmp, 'wo.c')
        open(w, 'w', encoding='utf-8').write(src)
        open(wo, 'w', encoding='utf-8').write(ablate(src, spans))
        worst = 0
        for cc in ccs:
            if not shutil.which(cc):
                res['compilers'][cc] = 'NOT_INSTALLED'
                continue
            aw, ew = compile_asm(cc, w, opt, list(cflags))
            awo, ewo = compile_asm(cc, wo, opt, list(cflags))
            if aw is None or awo is None:
                res['compilers'][cc] = 'COMPILE_ERROR: ' + (ew if aw is None else ewo)
                worst = max(worst, 2)
                continue
            bw, bwo = body_of(aw, fn), body_of(awo, fn)
            if bw is None or bwo is None:
                res['compilers'][cc] = 'FUNC_NOT_IN_ASM'
                worst = max(worst, 2)
                continue
            if bw == bwo:
                res['compilers'][cc] = 'ELIMINATED'
                worst = max(worst, 1)
            else:
                res['compilers'][cc] = 'SURVIVED'
        if not any(v in ('SURVIVED', 'ELIMINATED') or v.startswith('COMPILE') or v == 'FUNC_NOT_IN_ASM' for v in res['compilers'].values()):
            worst = 2
        res['result'] = {0: 'SURVIVED', 1: 'ELIMINATED', 2: 'UNDECIDED'}[worst]
        return res, worst
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description='消去処理が最適化の後に残っているかを確かめる')
    ap.add_argument('file')
    ap.add_argument('function')
    ap.add_argument('--cc', default='gcc,clang', help='カンマ区切り（既定 gcc,clang。clang-18 のような名前も可）')
    ap.add_argument('--opt', default='-O2')
    ap.add_argument('--cflags', default='', help='足す指定（空白区切り）')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()
    res, code = check(a.file, a.function, [c for c in a.cc.split(',') if c], a.opt, a.cflags.split())
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=1))
    else:
        print(f"{a.function}（{a.opt} {a.cflags}）：{res['result']}")
        for wtxt in res['wipes']:
            print('  消去処理:', wtxt)
        for cc, v in res['compilers'].items():
            print(f'  {cc}: {v}')
        if code == 1:
            print('  → 最適化で削除された。explicit_bzero などの削除されない書き方に直して，もう一度確かめる。')
    sys.exit(code)


if __name__ == '__main__':
    main()
