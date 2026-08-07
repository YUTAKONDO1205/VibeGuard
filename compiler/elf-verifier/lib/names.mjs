// Structural reading of symbol names.
//
// This is deliberately not a demangler. A demangler produces a sentence for a
// human; what the classifier needs is the opposite — the list of identifiers
// the mangled name is built out of, so that each one can be checked against the
// identifiers the translation unit actually contains. `_ZNK3BoxIiE5twiceEv`
// demangles to "Box<int>::twice() const", and the useful facts in it are the
// two source names `Box` and `twice`, not that sentence.
//
// Everything here is a grammar over the Itanium C++ ABI encoding plus the
// handful of reserved names clang and the GNU runtime synthesise. Nothing here
// is a list of symbols observed once on one machine.

/** Suffixes an optimiser appends to a name it has specialised or split. */
const OPT_SUFFIX = [
  /\.llvm\.\d+$/, // clang internalisation
  /\.cold(\.\d+)?$/,
  /\.part\.\d+$/,
  /\.constprop\.\d+$/,
  /\.isra\.\d+$/,
  /\.localalias(\.\d+)?$/,
  /\.\d+$/, // local-symbol uniquifier, e.g. __cxx_global_var_init.1
];

export function stripOptimiserSuffix(name) {
  let n = name;
  const applied = [];
  let changed = true;
  while (changed) {
    changed = false;
    for (const re of OPT_SUFFIX) {
      const m = n.match(re);
      if (m) {
        applied.push(m[0]);
        n = n.slice(0, n.length - m[0].length);
        changed = true;
        break;
      }
    }
  }
  return { base: n, stripped: applied };
}

/** A symbol table entry may carry the version in the name: `sym@GLIBC_2.34`. */
export function stripVersion(name) {
  const i = name.indexOf('@');
  return i === -1 ? { base: name, version: null } : { base: name.slice(0, i), version: name.slice(i) };
}

// Identifiers the ABI reserves: they appear as length-prefixed components in a
// mangled name but are never written in any source file, so requiring them to
// be found in the translation unit would reject every lambda and every
// anonymous namespace.
const ABI_COMPONENTS = new Set([
  '__invoke', // the lambda-to-function-pointer static thunk
  '_GLOBAL__N_1', // anonymous namespace
]);

/** clang spells a closure type `$_0`; GCC spells it `Ul…E_`. Both must pass. */
function isClosureComponent(id) {
  return /^\$_\d+$/.test(id) || /^_lambda\d*$/.test(id);
}

const SPECIAL_PREFIXES = [
  { re: /^_ZTVN?/, kind: 'vtable', category: 'generator-derived' },
  { re: /^_ZTTN?/, kind: 'vtt', category: 'generator-derived' },
  { re: /^_ZTIN?/, kind: 'typeinfo', category: 'generator-derived' },
  { re: /^_ZTSN?/, kind: 'typeinfo-name', category: 'generator-derived' },
  { re: /^_ZTC/, kind: 'construction-vtable', category: 'generator-derived' },
  { re: /^_ZThn?\d+_/, kind: 'thunk-non-virtual', category: 'generator-derived' },
  { re: /^_ZTv\d+_n\d+_/, kind: 'thunk-virtual', category: 'generator-derived' },
  { re: /^_ZTcv?\d+_n?\d+_\d+_n?\d+_/, kind: 'thunk-covariant', category: 'generator-derived' },
  { re: /^_ZGVZ?N?/, kind: 'guard-variable', category: 'generator-derived' },
  { re: /^_ZGRZ?N?/, kind: 'reference-temporary', category: 'generator-derived' },
];

/**
 * Pull the length-prefixed source-name components out of an Itanium mangled
 * name.
 *
 * The scan is the ABI's own `<source-name> ::= <positive length number>
 * <identifier>` production, applied greedily left to right. It has to run over
 * a name whose *prefix* has been stripped first: `_ZThn8_N1C1bEv` starts with
 * the thunk offset `8`, and reading that as a length yields the eight
 * characters `_N1C1bEv` as if they were one identifier — a wrong capture that
 * would then be looked for in the source and not found, i.e. a false positive
 * with a plausible story attached.
 */
export function mangledComponents(mangled) {
  const s = mangled;
  const out = [];
  let i = 0;
  while (i < s.length) {
    // `<ctor-dtor-name> ::= C1|C2|C3|CI1|CI2|D0|D1|D2` — the digit here is a
    // constructor/destructor variant, not a length. Measured: reading it as a
    // length turned `_ZN5ShapeD2Ev` into the component `Ev`, which of course is
    // in no source file, and every constructor and destructor in the vtable and
    // thunk controls came out Unexplained. Twenty-six false positives from one
    // missing production.
    if ((s[i] === 'C' || s[i] === 'D') && s.charCodeAt(i + 1) >= 0x30 && s.charCodeAt(i + 1) <= 0x35) {
      i += 2;
      continue;
    }
    const c = s.charCodeAt(i);
    if (c >= 0x30 && c <= 0x39) {
      let j = i;
      while (j < s.length && s.charCodeAt(j) >= 0x30 && s.charCodeAt(j) <= 0x39) j++;
      const n = Number(s.slice(i, j));
      if (n > 0 && j + n <= s.length) {
        const id = s.slice(j, j + n);
        if (/^[A-Za-z_$][A-Za-z0-9_$.]*$/.test(id)) {
          out.push(id);
          i = j + n;
          continue;
        }
      }
      i = j === i ? i + 1 : j;
      continue;
    }
    i++;
  }
  return out;
}

/**
 * Everything the classifier can learn about a name without looking at the
 * source. `kind` is what the name says it is; `components` is what has to be
 * accounted for before believing it.
 */
export function readName(rawName) {
  const { base: unversioned, version } = stripVersion(rawName);
  const { base: unsuffixed, stripped } = stripOptimiserSuffix(unversioned);
  const info = {
    raw: rawName,
    name: unversioned,
    version,
    optimiserSuffixes: stripped,
    mangled: false,
    kind: null,
    components: [],
    hasTemplateArgs: false,
    hasClosure: false,
  };

  // Reserved non-Itanium names the front end and the GNU runtime synthesise.
  let m;
  if ((m = unsuffixed.match(/^_GLOBAL__(sub_)?([ID])_(.+)$/))) {
    info.kind = m[2] === 'I' ? 'static-init-ctor' : 'static-init-dtor';
    info.originFile = m[3];
    return info;
  }
  if (/^__cxx_global_var_init$/.test(unsuffixed)) {
    info.kind = 'static-init-var';
    return info;
  }
  if ((m = unsuffixed.match(/^GCC_except_table\d+$/))) {
    info.kind = 'eh-except-table';
    return info;
  }
  if ((m = unsuffixed.match(/^DW\.ref\.(.+)$/))) {
    info.kind = 'eh-personality-ref';
    info.references = m[1];
    return info;
  }
  if ((m = unsuffixed.match(/^__odr_asan_gen_(.+)$/))) {
    info.kind = 'sanitizer-odr-indicator';
    info.references = m[1];
    return info;
  }
  if ((m = unsuffixed.match(/^(asan|msan|tsan|hwasan|ubsan|sancov)\.module_(ctor|dtor)$/))) {
    info.kind = 'sanitizer-module-init';
    info.sanitizer = m[1];
    return info;
  }
  if ((m = unsuffixed.match(/^__(start|stop)_(.+)$/))) {
    info.kind = 'encapsulation-symbol';
    info.encapsulates = m[2];
    info.encapsulationEnd = m[1];
    return info;
  }

  if (!unsuffixed.startsWith('_Z')) return info;

  info.mangled = true;
  let rest = unsuffixed;
  for (const p of SPECIAL_PREFIXES) {
    const mm = unsuffixed.match(p.re);
    if (mm) {
      info.kind = p.kind;
      rest = unsuffixed.slice(mm[0].length);
      break;
    }
  }
  if (info.kind === null) info.kind = 'itanium-entity';
  const comps = mangledComponents(rest);
  info.components = comps;
  info.hasClosure = comps.some(isClosureComponent);
  // `I…E` immediately after a source-name is the ABI's template-argument list.
  for (const c of comps) {
    const at = rest.indexOf(c);
    if (at > 0 && rest[at + c.length] === 'I') info.hasTemplateArgs = true;
  }
  return info;
}

/**
 * Split a name's components into the ones the source has to account for and the
 * ones the ABI accounts for on its own.
 */
export function attributableComponents(info) {
  const needSource = [];
  const abi = [];
  for (const c of info.components) {
    if (ABI_COMPONENTS.has(c) || isClosureComponent(c)) abi.push(c);
    else needSource.push(c);
  }
  return { needSource, abi };
}

/** Section names the ELF and C++ ABIs define, matched as a grammar. */
const ABI_SECTION = [
  /^$/,
  /^\.(text|data|bss|rodata|comment|interp|init|fini|preinit_array|init_array|fini_array)$/,
  /^\.(plt|plt\.sec|plt\.got|iplt|got|got\.plt|igot|igot\.plt)$/,
  /^\.(dynamic|dynsym|dynstr|symtab|strtab|shstrtab|symtab_shndx)$/,
  /^\.(hash|gnu\.hash|gnu\.version|gnu\.version_r|gnu\.version_d|gnu\.liblist|gnu\.warning.*)$/,
  /^\.(eh_frame|eh_frame_hdr|gcc_except_table|tm_clone_table)$/,
  /^\.(data\.rel\.ro|tdata|tbss|relro_padding)$/,
  /^\.note(\..+)?$/,
  /^\.debug_.*$/,
  /^\.(group|llvm_addrsig|llvm\..*|llvmbc|llvmcmd)$/,
  /^\.(ctors|dtors|jcr|stab|stabstr)$/,
  /^\.(gnu\.build\.attributes|gnu_debuglink|gnu_debugdata)$/,
];

const ABI_SECTION_PARENT = ['.text', '.rodata', '.data', '.bss', '.data.rel.ro', '.tdata', '.tbss', '.gcc_except_table', '.init_array', '.fini_array', '.gnu.linkonce'];

/** Sanitizer-owned sections. Only consulted when the flag key asked for one. */
const SANITIZER_SECTION = [/^asan_globals$/, /^asan_cstrings$/, /^__sancov_.*$/, /^sancov_.*$/, /^__msan_.*$/, /^__tsan_.*$/];

export function readSectionName(name) {
  if (name === null || name === undefined) return { name, kind: 'unnamed' };
  for (const re of ABI_SECTION) if (re.test(name)) return { name, kind: 'abi-section' };
  let m;
  if ((m = name.match(/^\.rela?\.(.+)$/))) return { name, kind: 'relocation-section', appliesTo: `.${m[1]}` };
  for (const parent of ABI_SECTION_PARENT) {
    if (name.startsWith(`${parent}.`)) {
      return { name, kind: 'abi-section-with-suffix', parent, suffix: name.slice(parent.length + 1) };
    }
  }
  for (const re of SANITIZER_SECTION) if (re.test(name)) return { name, kind: 'sanitizer-section' };
  return { name, kind: 'unknown' };
}

/** Symbols the static linker synthesises, independent of any input object. */
export const LINKER_SYNTHESISED = new Set([
  '_DYNAMIC', '_GLOBAL_OFFSET_TABLE_', '__ehdr_start', '__executable_start',
  '__bss_start', '_edata', '_end', '__end__', '_etext', 'etext', 'edata', 'end',
  '__init_array_start', '__init_array_end', '__fini_array_start', '__fini_array_end',
  '__preinit_array_start', '__preinit_array_end',
  '__rela_iplt_start', '__rela_iplt_end', '__rel_iplt_start', '__rel_iplt_end',
  '_TLS_MODULE_BASE_', '__tls_get_addr', '__GNU_EH_FRAME_HDR',
]);

/** Runtime-support names, each paired with the flag that has to have asked for it. */
export const RUNTIME_SUPPORT = [
  { re: /^__stack_chk_(fail|guard|fail_local)$/, requiresFlag: /^-fstack-protector/, family: 'stack-protector' },
  { re: /^__(\w+)_chk$/, requiresFlag: /^-D_FORTIFY_SOURCE/, family: 'fortify' },
  { re: /^__asan_/, requiresFlag: /^-fsanitize=.*address/, family: 'sanitizer-address' },
  { re: /^__lsan_/, requiresFlag: /^-fsanitize=.*(address|leak)/, family: 'sanitizer-leak' },
  { re: /^__sanitizer_/, requiresFlag: /^-fsanitize/, family: 'sanitizer-common' },
  { re: /^__ubsan_/, requiresFlag: /^-fsanitize/, family: 'sanitizer-undefined' },
  { re: /^__msan_/, requiresFlag: /^-fsanitize=.*memory/, family: 'sanitizer-memory' },
  { re: /^__tsan_/, requiresFlag: /^-fsanitize=.*thread/, family: 'sanitizer-thread' },
  { re: /^__sancov/, requiresFlag: /^-fsanitize-coverage/, family: 'sanitizer-coverage' },
  { re: /^__llvm_prf|^__profc_|^__profd_|^__profn_/, requiresFlag: /^-fprofile/, family: 'profile' },
  { re: /^_Unwind_/, requiresFlag: null, family: 'unwinder' },
  { re: /^__gxx_personality/, requiresFlag: null, family: 'eh-personality' },
  { re: /^__cxa_/, requiresFlag: null, family: 'cxx-abi' },
  { re: /^__gcc_personality/, requiresFlag: null, family: 'eh-personality' },
];
