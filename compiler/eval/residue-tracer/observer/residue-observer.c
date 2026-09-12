/*
 * residue-observer -- read the stack an attacker would read, one instruction
 * after the function that owned the secret has returned.
 *
 * WHAT THIS IS FOR. Every other measurement in compiler/eval/ asks whether the
 * WIPE INSTRUCTION survived compilation. That is a question about the artefact.
 * This asks whether the SECRET survived, which is a question about a running
 * process, and the two have different answers often enough that conflating them
 * is the point of the lane this file belongs to.
 *
 * WHY A SEPARATE PROCESS. The subject binary is never modified on disk and never
 * links a line of this file. Three alternatives were considered and rejected:
 *
 *   - gdb: absent on this box, and reading a verdict out of a tool's
 *     human-readable output is what interfaces.md section 4 forbids.
 *   - an observer translation unit linked into the subject: it would run on the
 *     very stack it wants to read, so its own frame would sit where the residue
 *     is and the reading would be of itself.
 *   - a core dump: /proc/sys/kernel/core_pattern here is a WSL pipe and
 *     `ulimit -c` is 0, so there is nothing to read; and the kernel writes the
 *     signal frame onto the dead stack anyway (Simon, Chisnall and Anderson,
 *     EuroS&P 2018, on the x64 red zone), which destroys part of the answer.
 *
 * THE STOP POINT is the subtle part, and it is not "just after the wipe". Above
 * -O0 the wipe is inlined and there is no wipe-function return to break on. What
 * exists at every level is the RETURN OF THE FUNCTION THAT OWNED THE BUFFER.
 * The procedure:
 *
 *   1. PTRACE_TRACEME + exec, so the first instruction is under control.
 *   2. int3 at the subject symbol's first byte. On the hit, [rsp] holds the
 *      return address -- this is function entry, before any prologue push.
 *   3. Restore that byte, rewind rip, int3 at the return address, continue.
 *   4. On the second hit, restore, rewind, and read. The owning frame is dead
 *      and nothing in the caller has executed.
 *
 * Both hits are checked rather than assumed: the second stop's rsp must be
 * exactly the entry rsp plus eight (the `ret` popped one word and nothing else
 * has run), and rip-1 must be the return address that was actually read at step
 * 2. A stop failing either check is reported as a failed stop and NEVER as a
 * residue reading -- "did not look" and "was not there" are different answers.
 *
 * WHAT IS READ: the general-purpose registers, rip and eflags (PTRACE_GETREGS),
 * xmm0-15 (PTRACE_GETFPREGS), and the stack window [rsp-below, rsp+above) via
 * process_vm_readv. ymm/zmm upper halves are NOT read: PTRACE_GETFPREGS returns
 * the legacy FXSAVE area, which holds xmm only. That is an UNOBSERVED, not an
 * absence, and the record lists it as one rather than implying otherwise. The
 * stack on BOTH sides of the window is unobserved too, and the record names both:
 * deeper than lo, and everything above hi up to the top of the stack.
 *
 * THE WINDOW IS NOT SELF-VALIDATING. This program reads the window it is told to
 * read; whether that window reached the buffer under test is decided outside it,
 * by comparing the subject function's frame depth (lib/frame.mjs, parsed from
 * objdump) against what was read. A run whose --below is shallower than the
 * subject frame produces a record that looks perfectly healthy, which is exactly
 * why that check is not left to this file.
 *
 * TWO NEEDLES, and this is what makes a NONE reading mean anything. --needle is
 * the subject's tracer. --control-needle is a second tracer the subject holds in
 * the SAME frame and deliberately never wipes. A cell whose control needle is
 * not fully readable measured nothing: the window, the reader or the stop was
 * wrong, and reporting its subject reading as "clean" would be reporting a
 * broken instrument as good news. The control is co-resident in the frame, not
 * merely in the run.
 *
 * Only the longest contiguous run is reported, not a boolean. Simon, Chisnall
 * and Anderson found most surviving residue to be short values around 64 bits,
 * left by the ABI, by calling conventions and by register spills; a search for
 * all 32 bytes would read CLEAN over an 8-byte fragment. Grading the run length
 * is the caller's job (lib/grade.mjs) -- this file counts.
 *
 * Build:  gcc-13 -O2 -std=gnu11 -Wall -Wextra -o residue-observer residue-observer.c
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define NEEDLE_MAX 4096
#define WINDOW_MAX (1u << 20)

static const char *GPR_NAMES[16] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
};

/* ------------------------------------------------------------------ output */

/*
 * The record is written even when the run fails, because a caller that receives
 * no file cannot tell a crash apart from a clean absence, and this lane's whole
 * argument is that those are different. On failure `ok` is false and `error`
 * carries the reason in this program's own words.
 */
static FILE *out_fp = NULL;
static char err_buf[512] = {0};

static void die_json(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err_buf, sizeof err_buf, fmt, ap);
    va_end(ap);
    if (out_fp) {
        fprintf(out_fp, "{\"schemaVersion\":\"residue-observation-v0\",\"ok\":false,\"error\":\"");
        for (const char *p = err_buf; *p; p++) {
            if (*p == '"' || *p == 92) fputc(92, out_fp);
            if (*p == '\n') { fputs("\\n", out_fp); continue; }
            fputc(*p, out_fp);
        }
        fprintf(out_fp, "\"}\n");
        fclose(out_fp);
    }
    fprintf(stderr, "residue-observer: %s\n", err_buf);
    exit(4);
}

static void hex_of(const unsigned char *b, size_t n, char *out) {
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = H[b[i] >> 4]; out[2 * i + 1] = H[b[i] & 15]; }
    out[2 * n] = 0;
}

/* -------------------------------------------------------------------- files */

static unsigned char *slurp(const char *path, size_t *len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    size_t cap = 1 << 16, n = 0;
    unsigned char *b = malloc(cap);
    if (!b) { close(fd); return NULL; }
    for (;;) {
        if (n == cap) {
            cap *= 2;
            unsigned char *nb = realloc(b, cap);
            if (!nb) { free(b); close(fd); return NULL; }
            b = nb;
        }
        ssize_t k = read(fd, b + n, cap - n);
        if (k < 0) { free(b); close(fd); return NULL; }
        if (k == 0) break;
        n += (size_t)k;
    }
    close(fd);
    *len = n;
    return b;
}

/* --------------------------------------------------------------------- ELF */

struct elfinfo {
    uint16_t type;
    uint64_t min_load_vaddr;
    uint64_t text_addr, text_size, text_off;
};

/*
 * The symbol address is read from .symtab, not from a tool's output, and the
 * subject is linked -no-pie so st_value IS the runtime address. That is checked
 * against /proc/<pid>/maps rather than believed: see maps_base().
 */
static int elf_scan(const unsigned char *f, size_t n, struct elfinfo *info) {
    if (n < sizeof(Elf64_Ehdr)) return -1;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)f;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return -1;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_ident[EI_DATA] != ELFDATA2LSB) return -1;
    info->type = eh->e_type;
    info->min_load_vaddr = UINT64_MAX;
    info->text_addr = info->text_size = info->text_off = 0;

    if (eh->e_phoff + (size_t)eh->e_phnum * eh->e_phentsize > n) return -1;
    for (unsigned i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(f + eh->e_phoff + (size_t)i * eh->e_phentsize);
        if (ph->p_type == PT_LOAD && ph->p_vaddr < info->min_load_vaddr) info->min_load_vaddr = ph->p_vaddr;
    }
    if (info->min_load_vaddr == UINT64_MAX) return -1;

    if (eh->e_shoff + (size_t)eh->e_shnum * eh->e_shentsize > n) return -1;
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(f + eh->e_shoff);
    if (eh->e_shstrndx >= eh->e_shnum) return -1;
    const char *shstr = (const char *)(f + sh[eh->e_shstrndx].sh_offset);
    for (unsigned i = 0; i < eh->e_shnum; i++) {
        if (strcmp(shstr + sh[i].sh_name, ".text") == 0) {
            info->text_addr = sh[i].sh_addr;
            info->text_size = sh[i].sh_size;
            info->text_off = sh[i].sh_offset;
        }
    }
    return info->text_size ? 0 : -1;
}

static int elf_symbol(const unsigned char *f, size_t n, const char *want, uint64_t *addr) {
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)f;
    if (eh->e_shoff + (size_t)eh->e_shnum * eh->e_shentsize > n) return -1;
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(f + eh->e_shoff);
    for (unsigned i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_SYMTAB) continue;
        if (sh[i].sh_link >= eh->e_shnum) continue;
        const char *str = (const char *)(f + sh[sh[i].sh_link].sh_offset);
        size_t count = sh[i].sh_size / sizeof(Elf64_Sym);
        const Elf64_Sym *sym = (const Elf64_Sym *)(f + sh[i].sh_offset);
        for (size_t k = 0; k < count; k++) {
            if (ELF64_ST_TYPE(sym[k].st_info) != STT_FUNC) continue;
            if (strcmp(str + sym[k].st_name, want) != 0) continue;
            *addr = sym[k].st_value;
            return 0;
        }
    }
    return -1;
}

/* ----------------------------------------------------------------- ptrace */

static long peek_word(pid_t pid, uint64_t addr, int *err) {
    errno = 0;
    long w = ptrace(PTRACE_PEEKTEXT, pid, (void *)(uintptr_t)addr, NULL);
    *err = (w == -1 && errno != 0);
    return w;
}

static int poke_word(pid_t pid, uint64_t addr, long w) {
    return ptrace(PTRACE_POKETEXT, pid, (void *)(uintptr_t)addr, (void *)w) == -1 ? -1 : 0;
}

static int set_bp(pid_t pid, uint64_t addr, long *orig) {
    int err = 0;
    long w = peek_word(pid, addr, &err);
    if (err) return -1;
    *orig = w;
    return poke_word(pid, addr, (w & ~0xffL) | 0xccL);
}

/*
 * The load base the process actually got, taken from the lowest mapping of the
 * executable's own path in /proc/<pid>/maps. -no-pie makes this equal to the
 * page-aligned lowest PT_LOAD vaddr; the point of reading it is that the
 * equality is asserted rather than assumed, so a build that silently came out
 * position-independent is a failed run instead of a wrong address.
 */
static int maps_base(pid_t pid, const char *exe_real, uint64_t *base) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", (int)pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[4096];
    uint64_t lo = UINT64_MAX;
    while (fgets(line, sizeof line, fp)) {
        char *sp = strchr(line, '/');
        if (!sp) continue;
        size_t l = strlen(sp);
        while (l && (sp[l - 1] == '\n' || sp[l - 1] == ' ')) sp[--l] = 0;
        if (strcmp(sp, exe_real) != 0) continue;
        uint64_t a = strtoull(line, NULL, 16);
        if (a < lo) lo = a;
    }
    fclose(fp);
    if (lo == UINT64_MAX) return -1;
    *base = lo;
    return 0;
}

static ssize_t read_remote(pid_t pid, uint64_t addr, unsigned char *dst, size_t len) {
    struct iovec l = { .iov_base = dst, .iov_len = len };
    struct iovec r = { .iov_base = (void *)(uintptr_t)addr, .iov_len = len };
    return process_vm_readv(pid, &l, 1, &r, 1, 0);
}

/* ------------------------------------------------------------------ search */

/*
 * The longest contiguous run of needle bytes anywhere in the haystack, i.e. the
 * longest common substring of the two. Brute force: the haystack is a few
 * kilobytes and the needle is 32 bytes, so this is a few million comparisons and
 * a smarter algorithm would only be harder to check.
 *
 * A boolean "is the whole needle there" would be the wrong instrument. The
 * fragment case is the one the prior work found in the field.
 */
static size_t longest_run(const unsigned char *hay, size_t hn,
                          const unsigned char *ned, size_t nn,
                          size_t *hay_off, size_t *ned_off) {
    size_t best = 0;
    *hay_off = 0; *ned_off = 0;
    if (!hn || !nn) return 0;
    for (size_t i = 0; i < hn; i++) {
        for (size_t j = 0; j < nn; j++) {
            if (hay[i] != ned[j]) continue;
            size_t k = 0;
            while (i + k < hn && j + k < nn && hay[i + k] == ned[j + k]) k++;
            if (k > best) { best = k; *hay_off = i; *ned_off = j; }
            if (best == nn) return best;
        }
    }
    return best;
}

struct hit { size_t len, hay_off, ned_off; };

/*
 * The best run over a set of equal-width register slots, and which slot it was
 * in. Scanned slot by slot rather than over a concatenation: a run spanning two
 * adjacent registers would be an artefact of the order they were written in.
 */
static struct hit scan_slots(const unsigned char *base, size_t slots, size_t width,
                             const unsigned char *ned, size_t nn, int *which) {
    struct hit best = {0, 0, 0};
    *which = -1;
    for (size_t s = 0; s < slots; s++) {
        size_t ho, no;
        size_t l = longest_run(base + s * width, width, ned, nn, &ho, &no);
        if (l > best.len) { best.len = l; best.hay_off = ho; best.ned_off = no; *which = (int)s; }
    }
    return best;
}

/* -------------------------------------------------------------------- main */

static void usage(void) {
    fprintf(stderr,
        "usage: residue-observer --needle F --control-needle F --symbol NAME --out F --window F\n"
        "                        [--below N] [--above N] -- EXE [ARGS...]\n");
    exit(2);
}

int main(int argc, char **argv) {
    const char *needle_path = NULL, *ctl_path = NULL, *symbol = NULL;
    const char *out_path = NULL, *window_path = NULL;
    size_t below = 4096, above = 64;
    int sep = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) { sep = i; break; }
        if (i + 1 >= argc) usage();
        if (strcmp(argv[i], "--needle") == 0) needle_path = argv[++i];
        else if (strcmp(argv[i], "--control-needle") == 0) ctl_path = argv[++i];
        else if (strcmp(argv[i], "--symbol") == 0) symbol = argv[++i];
        else if (strcmp(argv[i], "--out") == 0) out_path = argv[++i];
        else if (strcmp(argv[i], "--window") == 0) window_path = argv[++i];
        else if (strcmp(argv[i], "--below") == 0) below = strtoul(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--above") == 0) above = strtoul(argv[++i], NULL, 0);
        else usage();
    }
    if (!needle_path || !ctl_path || !symbol || !out_path || !window_path) usage();
    if (sep < 0 || sep + 1 >= argc) usage();
    if (below + above == 0 || below + above > WINDOW_MAX) usage();

    out_fp = fopen(out_path, "w");
    if (!out_fp) { fprintf(stderr, "residue-observer: cannot write --out\n"); return 4; }

    char **child_argv = &argv[sep + 1];
    const char *exe = child_argv[0];

    size_t nlen = 0, clen = 0, flen = 0;
    unsigned char *needle = slurp(needle_path, &nlen);
    if (!needle || nlen == 0 || nlen > NEEDLE_MAX) die_json("needle file unreadable or of an unusable length");
    unsigned char *ctl = slurp(ctl_path, &clen);
    if (!ctl || clen == 0 || clen > NEEDLE_MAX) die_json("control-needle file unreadable or of an unusable length");
    unsigned char *file = slurp(exe, &flen);
    if (!file) die_json("cannot read the subject executable");

    char exe_real[4096];
    if (!realpath(exe, exe_real)) die_json("cannot resolve the subject executable path");
    const char *exe_base = strrchr(exe_real, '/');
    exe_base = exe_base ? exe_base + 1 : exe_real;

    struct elfinfo ei;
    if (elf_scan(file, flen, &ei) != 0) die_json("the subject is not an ELF64 LSB image with a .text section");
    uint64_t sym_addr = 0;
    if (elf_symbol(file, flen, symbol, &sym_addr) != 0)
        die_json("symbol %s is not a STT_FUNC in the subject .symtab", symbol);

    pid_t pid = fork();
    if (pid < 0) die_json("fork failed: %s", strerror(errno));
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) _exit(126);
#ifdef ADDR_NO_RANDOMIZE
        /* Attempted, not asserted. Nothing in the measurement depends on it: the
         * window is taken relative to rsp, and no grading rule reads an absolute
         * address. Measured on this kernel it does NOT take effect -- two runs of
         * the same binary recorded window.lo 140734159020752 and 140729091150416
         * -- so the recorded bounds are per-run facts and not comparable between
         * runs. They are kept because they say where the reading came from. */
        (void)personality(ADDR_NO_RANDOMIZE);
#endif
        execv(exe, child_argv);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) die_json("waitpid after exec failed: %s", strerror(errno));
    if (!WIFSTOPPED(status)) die_json("the child did not stop at exec (status %d)", status);
    ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)(uintptr_t)PTRACE_O_EXITKILL);

    uint64_t base = 0;
    if (maps_base(pid, exe_real, &base) != 0)
        die_json("the executable has no mapping of its own path in /proc/<pid>/maps");
    uint64_t expected_base = ei.min_load_vaddr & ~(uint64_t)0xfff;
    if (base != expected_base)
        die_json("load bias is not zero: mapped at 0x%llx, lowest PT_LOAD page 0x%llx. Link the subject -no-pie.",
                 (unsigned long long)base, (unsigned long long)expected_base);

    long orig_entry = 0;
    if (set_bp(pid, sym_addr, &orig_entry) != 0)
        die_json("cannot plant the entry breakpoint at 0x%llx", (unsigned long long)sym_addr);

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
        die_json("PTRACE_CONT to the entry breakpoint failed: %s", strerror(errno));
    if (waitpid(pid, &status, 0) < 0) die_json("waitpid at the entry breakpoint failed: %s", strerror(errno));
    if (WIFEXITED(status)) die_json("the child exited (code %d) before %s was reached", WEXITSTATUS(status), symbol);
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        die_json("the child stopped on signal %d rather than SIGTRAP at the entry breakpoint",
                 WIFSTOPPED(status) ? WSTOPSIG(status) : -1);

    struct user_regs_struct r_entry;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r_entry) == -1)
        die_json("PTRACE_GETREGS at entry failed: %s", strerror(errno));
    if (r_entry.rip - 1 != sym_addr)
        die_json("the entry trap is at 0x%llx, not one past %s at 0x%llx",
                 (unsigned long long)r_entry.rip, symbol, (unsigned long long)sym_addr);

    /* At the first byte of the function nothing has been pushed, so [rsp] is the
     * return address. Everything after this depends on that being true, which is
     * why the breakpoint is on the symbol first byte and not on a line. */
    uint64_t rsp_entry = r_entry.rsp;
    uint64_t ret_addr = 0;
    if (read_remote(pid, rsp_entry, (unsigned char *)&ret_addr, 8) != 8)
        die_json("cannot read the return address at [rsp] on entry");

    if (poke_word(pid, sym_addr, orig_entry) != 0) die_json("cannot restore the entry byte");
    r_entry.rip = sym_addr;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &r_entry) == -1) die_json("cannot rewind rip to %s", symbol);

    long orig_ret = 0;
    if (set_bp(pid, ret_addr, &orig_ret) != 0)
        die_json("cannot plant the return breakpoint at 0x%llx", (unsigned long long)ret_addr);

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
        die_json("PTRACE_CONT to the return breakpoint failed: %s", strerror(errno));
    if (waitpid(pid, &status, 0) < 0) die_json("waitpid at the return breakpoint failed: %s", strerror(errno));
    if (WIFEXITED(status)) die_json("the child exited (code %d) before returning from %s", WEXITSTATUS(status), symbol);
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        die_json("the child stopped on signal %d rather than SIGTRAP at the return breakpoint",
                 WIFSTOPPED(status) ? WSTOPSIG(status) : -1);

    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) == -1) die_json("PTRACE_GETREGS at the stop failed: %s", strerror(errno));
    struct user_fpregs_struct fp;
    memset(&fp, 0, sizeof fp);
    int fp_ok = ptrace(PTRACE_GETFPREGS, pid, NULL, &fp) != -1;

    int stop_rip_matched = (r.rip - 1 == ret_addr);
    /* `ret` popped exactly one word and the caller has executed nothing since,
     * so this is the only rsp the stop can legitimately have. A recursive call, a
     * second call site reaching the same return address, or a longjmp would all
     * land here with a different rsp, and each would make the window point at a
     * frame that is not the one under test. */
    uint64_t rsp_expected = rsp_entry + 8;
    int stop_rsp_matched = (r.rsp == rsp_expected);

    if (poke_word(pid, ret_addr, orig_ret) != 0) die_json("cannot restore the return-address byte");
    if (stop_rip_matched) { r.rip = ret_addr; ptrace(PTRACE_SETREGS, pid, NULL, &r); }

    uint64_t lo = r.rsp - below, hi = r.rsp + above;
    size_t want = (size_t)(hi - lo);
    unsigned char *win = calloc(want, 1);
    if (!win) die_json("cannot allocate the stack window");
    ssize_t got = read_remote(pid, lo, win, want);
    if (got < 0) got = 0;

    FILE *wf = fopen(window_path, "wb");
    if (!wf) die_json("cannot write --window");
    if (got > 0) fwrite(win, 1, (size_t)got, wf);
    fclose(wf);

    /* Did the text this run patched come back byte for byte? Compared against
     * the FILE, not against a remembered copy of what was written, so a restore
     * that wrote the wrong word is caught rather than confirmed. */
    unsigned char *text_now = malloc((size_t)ei.text_size);
    long long text_mismatch = -1;
    int text_compared = 0;
    if (text_now && read_remote(pid, ei.text_addr, text_now, (size_t)ei.text_size) == (ssize_t)ei.text_size) {
        text_compared = 1;
        const unsigned char *text_file = file + ei.text_off;
        for (uint64_t i = 0; i < ei.text_size; i++) {
            if (text_now[i] != text_file[i]) { text_mismatch = (long long)i; break; }
        }
    }

    ptrace(PTRACE_KILL, pid, NULL, NULL);
    waitpid(pid, &status, 0);

    /* ---- searches ---- */
    size_t ho = 0, no = 0;
    size_t win_run = longest_run(win, (size_t)got, needle, nlen, &ho, &no);
    size_t cho = 0, cno = 0;
    size_t win_ctl_run = longest_run(win, (size_t)got, ctl, clen, &cho, &cno);

    unsigned char gpr[16][8];
    uint64_t gv[16] = { r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp, r.rsp,
                        r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15 };
    for (int i = 0; i < 16; i++) for (int b = 0; b < 8; b++) gpr[i][b] = (unsigned char)(gv[i] >> (8 * b));

    int gpr_which = -1, xmm_which = -1, gprc_which = -1, xmmc_which = -1;
    struct hit gpr_hit = scan_slots((const unsigned char *)gpr, 16, 8, needle, nlen, &gpr_which);
    struct hit gprc_hit = scan_slots((const unsigned char *)gpr, 16, 8, ctl, clen, &gprc_which);
    const unsigned char *xmm = (const unsigned char *)fp.xmm_space;
    struct hit xmm_hit = {0, 0, 0}, xmmc_hit = {0, 0, 0};
    if (fp_ok) {
        xmm_hit = scan_slots(xmm, 16, 16, needle, nlen, &xmm_which);
        xmmc_hit = scan_slots(xmm, 16, 16, ctl, clen, &xmmc_which);
    }

    /* ---- record ---- */
    char hexbuf[64 * 2 + 1];
    fprintf(out_fp, "{\n");
    fprintf(out_fp, "  \"schemaVersion\": \"residue-observation-v0\",\n");
    fprintf(out_fp, "  \"ok\": true,\n  \"error\": null,\n");
    fprintf(out_fp, "  \"symbol\": \"%s\",\n", symbol);
    fprintf(out_fp, "  \"exeBasename\": \"%s\",\n", exe_base);
    fprintf(out_fp, "  \"elf\": {\"type\": %u, \"minLoadVaddr\": %llu, \"textAddr\": %llu, \"textSize\": %llu},\n",
            (unsigned)ei.type, (unsigned long long)ei.min_load_vaddr,
            (unsigned long long)ei.text_addr, (unsigned long long)ei.text_size);
    fprintf(out_fp, "  \"map\": {\"base\": %llu, \"expectedBase\": %llu, \"biasZero\": true},\n",
            (unsigned long long)base, (unsigned long long)expected_base);
    fprintf(out_fp, "  \"entry\": {\"addr\": %llu, \"rsp\": %llu, \"returnAddr\": %llu},\n",
            (unsigned long long)sym_addr, (unsigned long long)rsp_entry, (unsigned long long)ret_addr);
    fprintf(out_fp, "  \"stop\": {\"expectedRip\": %llu, \"rip\": %llu, \"matched\": %s, "
                    "\"expectedRsp\": %llu, \"rsp\": %llu, \"rspMatched\": %s},\n",
            (unsigned long long)ret_addr,
            (unsigned long long)(stop_rip_matched ? ret_addr : r.rip - 1),
            stop_rip_matched ? "true" : "false",
            (unsigned long long)rsp_expected, (unsigned long long)r.rsp,
            stop_rsp_matched ? "true" : "false");
    fprintf(out_fp, "  \"eflags\": %llu,\n", (unsigned long long)r.eflags);
    fprintf(out_fp, "  \"window\": {\"lo\": %llu, \"hi\": %llu, \"requested\": %zu, \"bytesRead\": %zd},\n",
            (unsigned long long)lo, (unsigned long long)hi, want, got);
    fprintf(out_fp, "  \"text\": {\"compared\": %s, \"size\": %llu, \"restoredMatchesFile\": %s, "
                    "\"firstMismatchOffset\": %lld},\n",
            text_compared ? "true" : "false", (unsigned long long)ei.text_size,
            (text_compared && text_mismatch < 0) ? "true" : "false", text_mismatch);
    fprintf(out_fp, "  \"fpregsRead\": %s,\n", fp_ok ? "true" : "false");
    /* Both sides of the window are named. The list used to say only
     * "stack-below-the-window", which left the caller frames above the
     * window -- everything from hi up to the top of the stack -- unnamed,
     * even though this file's own prose and the README already counted them
     * out. A machine-readable field narrower than the prose is the half a
     * script would believe. lib/manifest.mjs carries the same list for a row
     * with no record, and test/observer-record.test.mjs holds the two
     * identical. */
    fprintf(out_fp, "  \"unobserved\": [\"ymm-upper\", \"zmm-upper\", \"heap\", \"other-threads\", "
                    "\"kernel-saved-state\", \"stack-below-the-window\", "
                    "\"stack-above-the-window\"],\n");
    fprintf(out_fp, "  \"needleLen\": %zu,\n  \"controlNeedleLen\": %zu,\n", nlen, clen);
    fprintf(out_fp, "  \"stack\": {\"longestRunBytes\": %zu, \"windowOffset\": %zu, \"needleOffset\": %zu},\n",
            win_run, ho, no);
    fprintf(out_fp, "  \"stackControl\": {\"longestRunBytes\": %zu, \"windowOffset\": %zu, \"needleOffset\": %zu},\n",
            win_ctl_run, cho, cno);
    fprintf(out_fp, "  \"gpr\": {\"longestRunBytes\": %zu, \"slot\": %d},\n", gpr_hit.len, gpr_which);
    fprintf(out_fp, "  \"gprControl\": {\"longestRunBytes\": %zu, \"slot\": %d},\n", gprc_hit.len, gprc_which);
    fprintf(out_fp, "  \"xmm\": {\"longestRunBytes\": %zu, \"slot\": %d},\n", xmm_hit.len, xmm_which);
    fprintf(out_fp, "  \"xmmControl\": {\"longestRunBytes\": %zu, \"slot\": %d},\n", xmmc_hit.len, xmmc_which);
    fprintf(out_fp, "  \"gprHex\": [");
    for (int i = 0; i < 16; i++) {
        hex_of(gpr[i], 8, hexbuf);
        fprintf(out_fp, "%s\"%s\"", i ? ", " : "", hexbuf);
    }
    fprintf(out_fp, "],\n  \"gprNames\": [");
    for (int i = 0; i < 16; i++) fprintf(out_fp, "%s\"%s\"", i ? ", " : "", GPR_NAMES[i]);
    fprintf(out_fp, "],\n  \"xmmHex\": [");
    for (int i = 0; i < 16; i++) {
        if (fp_ok) hex_of(xmm + i * 16, 16, hexbuf); else hexbuf[0] = 0;
        fprintf(out_fp, "%s\"%s\"", i ? ", " : "", hexbuf);
    }
    fprintf(out_fp, "]\n}\n");
    fclose(out_fp);

    free(win); free(text_now); free(file); free(needle); free(ctl);
    /* Exit 0 means the instrument ran to its stop and wrote a record. It does
     * NOT mean the stop was the right one: `stop.matched` and `stop.rspMatched`
     * say that, and the grader refuses to turn a failed stop into a verdict. */
    return 0;
}
