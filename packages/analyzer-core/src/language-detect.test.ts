import { describe, expect, it } from 'vitest';
import { detectLanguageFromPath } from './language-detect.js';

// VG-EMB 17c EMB-LANG — the embedded C/C++/Arduino extension mappings.
//
// These are pinned separately from the EXT_TO_LANGUAGE <-> LINE_COMMENT_SPECS
// sync test (language-comment-sync.test.ts, which proves every mapped language
// has a comment spec). Here we pin the mapping itself: that .ino and the C++
// header/impl extensions resolve to a language the rules engine already knows,
// and — the part a sync test cannot see — that adding them did NOT shadow or
// get shadowed by an existing extension via `endsWith`.
describe('embedded extension mapping (17c)', () => {
  it('maps Arduino sketches and C++ dialect extensions to cpp', () => {
    expect(detectLanguageFromPath('sketch.ino')).toBe('cpp');
    expect(detectLanguageFromPath('driver.hh')).toBe('cpp');
    expect(detectLanguageFromPath('module.cxx')).toBe('cpp');
    expect(detectLanguageFromPath('inline_impl.ipp')).toBe('cpp');
  });

  it('is case-insensitive (uppercase extensions resolve too)', () => {
    expect(detectLanguageFromPath('SKETCH.INO')).toBe('cpp');
    expect(detectLanguageFromPath('Driver.HH')).toBe('cpp');
  });

  // The `endsWith` scan returns the FIRST matching entry, so a new extension
  // that ends with an existing one (or vice versa) would silently shadow it.
  // `.hh` does not end with `.h` (the dot is compared: "x.hh" ends with "hh"),
  // and none of the four additions collide with the pre-existing c/cpp set.
  it('does not disturb the pre-existing C/C++ extensions', () => {
    expect(detectLanguageFromPath('main.c')).toBe('c');
    expect(detectLanguageFromPath('header.h')).toBe('c');
    expect(detectLanguageFromPath('app.cpp')).toBe('cpp');
    expect(detectLanguageFromPath('app.hpp')).toBe('cpp');
    expect(detectLanguageFromPath('legacy.cc')).toBe('cpp');
  });

  it('still returns undefined for an unmapped extension', () => {
    expect(detectLanguageFromPath('config.hcl')).toBeUndefined();
    // `.in` is a common autotools template extension and must NOT be caught by
    // the `.ino` entry — `endsWith('.ino')` is false for a path ending `.in`.
    expect(detectLanguageFromPath('Makefile.in')).toBeUndefined();
  });
});
