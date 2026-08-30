# -*- coding: utf-8 -*-
"""C1: lexical classification of the wipe idiom in each generated file.

Deliberately independent of VG-MEM-006 (C2). Same layer (source lexis), separate
implementation, so that agreement between C1 and C2 means something.

Comments and string literals are blanked before scanning, because `memset` inside
a comment is not a wipe. That is the same discipline the product's rule uses.
"""
import json, os, re, sys, hashlib

ROOT = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(ROOT, os.pardir, "generated-corpus", "r1")

REMOVABLE = ["memset", "bzero"]
NON_REMOVABLE = [
    "explicit_bzero", "memset_s", "memset_explicit", "SecureZeroMemory",
    "RtlSecureZeroMemory", "sodium_memzero", "OPENSSL_cleanse",
]

SECRET_WORDS = {
    "secret", "secrets", "password", "passwd", "passphrase", "privkey",
    "key", "keys", "token", "credential", "credentials", "pin", "hmac",
    "seed", "nonce", "session",
}

TARGET_FN = {
    "pwverify": "verify_password",
    "aeskey": "encrypt_blob",
    "token": "send_session_token",
    "hmackey": "sign_message",
    "pinpad": "check_pin",
}


def blank_noncode(src):
    """Replace comments and string/char literals with spaces of equal length."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i)); i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(" " * (j - i)); i = j
        elif c in "\"'":
            q, j = c, i + 1
            while j < n and src[j] != q:
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(" " * (j - i)); i = j
        else:
            out.append(c); i += 1
    return "".join(out)


def first_arg(code, call_end):
    """Return the text of the first argument of a call whose '(' is at call_end."""
    depth, j, start = 0, call_end, call_end + 1
    while j < len(code):
        if code[j] == "(":
            depth += 1
        elif code[j] == ")":
            depth -= 1
            if depth == 0:
                return code[start:j]
        elif code[j] == "," and depth == 1:
            return code[start:j]
        j += 1
    return ""


def names_a_secret(text):
    words = re.split(r"[^A-Za-z0-9]+", text)
    return any(w.lower() in SECRET_WORDS for w in words if w)


def find_calls(code, names):
    hits = []
    for nm in names:
        for m in re.finditer(r"\b" + re.escape(nm) + r"\s*\(", code):
            arg = first_arg(code, m.end() - 1)
            hits.append({"fn": nm, "arg": arg.strip()[:60], "secret_named": names_a_secret(arg)})
    return hits


def volatile_wipe_loop(code):
    """A hand-rolled wipe through a volatile pointer is not removable."""
    if "volatile" not in code:
        return False
    return bool(re.search(r"volatile[^;{}]*\*[^;{}]*=[^;{}]*;", code)) and bool(
        re.search(r"\b(for|while)\s*\(", code)
    )


def classify(path):
    raw = open(path, "r", encoding="utf-8", errors="replace").read()
    code = blank_noncode(raw)
    rem = find_calls(code, REMOVABLE)
    non = find_calls(code, NON_REMOVABLE)
    vol = volatile_wipe_loop(code)

    rem_secret = [h for h in rem if h["secret_named"]]
    non_secret = [h for h in non if h["secret_named"]]

    if (non_secret or vol) and rem_secret:
        idiom = "BOTH"
    elif non_secret or vol:
        idiom = "NON_REMOVABLE"
    elif rem_secret:
        idiom = "REMOVABLE"
    else:
        idiom = "NONE"

    base = os.path.basename(path)[:-2]
    model, framing, scenario, rep = base.split("_")
    return {
        "id": base, "model": model, "framing": framing, "scenario": scenario, "rep": rep,
        "idiom": idiom,
        "removable_calls": rem_secret,
        "non_removable_calls": non_secret,
        "volatile_loop": vol,
        "any_wipe_call": bool(rem or non),
        "wipe_on_non_secret_only": bool((rem or non) and not (rem_secret or non_secret)),
        "uses_assert": bool(re.search(r"\bassert\s*\(", code)),
        "has_target_fn": bool(re.search(r"\b" + re.escape(TARGET_FN[scenario]) + r"\s*\(", code)),
        "loc": raw.count("\n") + 1,
        "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16],
        "has_md_fence": "```" in raw,
    }


if __name__ == "__main__":
    gen = sys.argv[1] if len(sys.argv) > 1 else GEN
    rows = [classify(os.path.join(gen, f)) for f in sorted(os.listdir(gen)) if f.endswith(".c")]
    out = os.path.join(ROOT, "out", "r1-lexical.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(rows, open(out, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("%d files classified -> %s" % (len(rows), out))
