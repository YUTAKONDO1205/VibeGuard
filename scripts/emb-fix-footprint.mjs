// VG-EMB 18b — measure the firmware footprint of embedded fixes, honestly.
//
// For each pure-C before/after fix pair, cross-compile both with the arm
// toolchain and diff `arm-none-eabi-size`. When the toolchain is absent (CI,
// most dev boxes) every delta is reported as "not measured (toolchain-absent)"
// — the null path is the default, and a null is NEVER rendered as 0.
//
// Only pure-C pairs are measured: newlib ships string.h/stdio.h so they compile
// standalone. Arduino-API fixes (WiFi/Serial) need a core to compile, so they
// are reported as not-applicable rather than measured against fake stubs.
//
// Run: node scripts/emb-fix-footprint.mjs
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  probeArmToolchain,
  parseSizeOutput,
  measureFootprint,
  renderFootprint,
} from '../packages/remediation-engine/dist/footprint.js';

const spawn = (cmd, args) => {
  const r = spawnSync(cmd, args, { encoding: 'utf8' });
  return { status: r.status, stdout: r.stdout ?? '', error: r.error };
};

const GCC = 'arm-none-eabi-gcc';
const SIZE = 'arm-none-eabi-size';

function compileAndSize(source) {
  const dir = mkdtempSync(join(tmpdir(), 'vg-fp-'));
  try {
    const c = join(dir, 'u.c');
    const o = join(dir, 'u.o');
    writeFileSync(c, source, 'utf8');
    const gcc = spawnSync(GCC, ['-mcpu=cortex-m4', '-Os', '-c', c, '-o', o], { encoding: 'utf8' });
    if (gcc.status !== 0) return null;
    const size = spawnSync(SIZE, [o], { encoding: 'utf8' });
    if (size.status !== 0) return null;
    return parseSizeOutput(size.stdout ?? '');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Pure-C fix pairs (VG-MEM family): the shape a real fix would produce.
const PAIRS = [
  {
    id: 'VG-MEM-002 strcpy → snprintf',
    before: '#include <string.h>\nvoid f(char*d,const char*s){strcpy(d,s);}\n',
    after: '#include <stdio.h>\nvoid f(char*d,const char*s){snprintf(d,32,"%s",s);}\n',
  },
  {
    id: 'VG-MEM-001 gets → fgets',
    before: '#include <stdio.h>\nvoid f(char*b){gets(b);}\n',
    after: '#include <stdio.h>\nvoid f(char*b){fgets(b,64,stdin);}\n',
  },
];

const probe = () => probeArmToolchain(spawn);
const { present, version } = probe();

console.log('# VG-EMB 18b — embedded fix footprint\n');
console.log(present ? `Toolchain: ${version}\n` : 'Toolchain: arm-none-eabi absent — footprints are NULL by honest default.\n');
console.log('| fix | footprint |');
console.log('|---|---|');
for (const p of PAIRS) {
  const fp = measureFootprint(p.before, p.after, { probe, compileAndSize });
  console.log(`| ${p.id} | ${renderFootprint(fp)} |`);
}
console.log('\n(Arduino-API fixes are not-applicable here — they need a board core to compile.)');
