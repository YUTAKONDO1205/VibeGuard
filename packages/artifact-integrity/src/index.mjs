// Public surface. Named explicitly rather than with `export *`: three of these
// modules deliberately re-export names from each other, and an ambiguous star
// export is dropped silently in ESM rather than reported — which would make
// `STATE` and `readElf` disappear from this entry point with no error anywhere.

export {
  readElf, linkForm, isDynamicallyLinked,
  undefinedSymbols, definedSymbols, exportedSymbols,
  neededLibraries, runPaths, pltCallSites, dynstrNames, initFunctions,
  dynTag, dynTags, dynFlagValue,
  ET, PT, PF, SHT, SHF, STB, STT, SHN, DT, DF, DF_1, R_X86_64, NT_GNU_BUILD_ID,
} from './elf.mjs';

export {
  STATE, ALL_STATES, HARDENING_PROPERTIES,
  decidePie, decideNx, decideRelro, decideStackProtector, decideFortify,
  decideBuildId, decideNoWritableExecutable, findWritableExecutable, decideAll,
} from './properties.mjs';

export {
  extractStrings, sectionAt, findForbiddenStrings, checkResidueControls,
  debugSections, findBuildPaths, buildPathShapes, redactPath,
} from './residue.mjs';

export {
  observe, verifyArtifact, verifyPath, exitCodeFor,
  ART, SEVERITY,
  EXIT_OK, EXIT_TOOL_FAILED, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_INTEGRITY,
} from './verify.mjs';
