/**
 * Byte scanning, independently of the observer.
 *
 * The C observer counts the longest run of tracer bytes it can find, and this
 * module counts it again in a second language over the window the observer
 * dumped to disk. The runner compares the two and refuses a cell where they
 * disagree. That is not belt-and-braces: the observer is the only component in
 * this lane that both chooses where to look and decides what it saw, and a bug
 * in its search would be invisible in its own record.
 *
 * WHY THE LONGEST RUN AND NOT A BOOLEAN. Simon, Chisnall and Anderson (EuroS&P
 * 2018) measured what actually survives an erasure on real crypto code and found
 * it is mostly short -- values around 64 bits, left by the ABI, by calling
 * conventions and by register spills. A search for all 32 tracer bytes would
 * report CLEAN over an eight-byte fragment of a key. So the instrument counts a
 * length and the grader thresholds it, and the threshold is stated rather than
 * implied.
 *
 * WHY EIGHT BYTES IS THE FLOOR. The tracer is uniform random, so a run of k
 * bytes arising by chance at one position has probability 2^-8k; over a 4 KiB
 * window and a 32-byte needle there are fewer than 2^17 (position, offset) pairs,
 * so a spurious 8-byte run has probability below 2^-47. Four bytes would not be
 * safe by that argument -- a 4 KiB window contains 32-bit coincidences.
 *
 * Nothing here reads a file, runs a compiler or knows what a cell is.
 */

/** The shortest run this lane is willing to call residue. See the header. */
export const PARTIAL_FLOOR = 8;

/** The residue vocabulary. NOT_OBSERVED is section 3's own word and is never a reading. */
export const RESIDUE = Object.freeze(['NONE', 'PARTIAL', 'FULL', 'NOT_OBSERVED']);

/**
 * The longest contiguous run of `needle` bytes anywhere in `hay`: the longest
 * common substring of the two. Brute force, for the reason the C side is brute
 * force -- a few kilobytes against 32 bytes is a few million comparisons, and a
 * smarter algorithm would only be harder to check against the other
 * implementation.
 *
 * @param {Uint8Array} hay
 * @param {Uint8Array} needle
 * @returns {{len: number, hayOffset: number, needleOffset: number}}
 */
export function longestRun(hay, needle) {
  const out = { len: 0, hayOffset: 0, needleOffset: 0 };
  if (!hay || !needle || hay.length === 0 || needle.length === 0) return out;
  for (let i = 0; i < hay.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i] !== needle[j]) continue;
      let k = 0;
      while (i + k < hay.length && j + k < needle.length && hay[i + k] === needle[j + k]) k++;
      if (k > out.len) { out.len = k; out.hayOffset = i; out.needleOffset = j; }
      if (out.len === needle.length) return out;
    }
  }
  return out;
}

/**
 * The best run over a set of equal-width slots, and which slot held it.
 *
 * Registers are scanned slot by slot rather than over a concatenation of them: a
 * run that straddled two adjacent registers would be an artefact of the order
 * this code happened to write them in, not something a process ever held.
 *
 * @param {Uint8Array[]} slots
 * @param {Uint8Array} needle
 * @returns {{len: number, slot: number, hayOffset: number, needleOffset: number}}
 */
export function longestRunOverSlots(slots, needle) {
  const out = { len: 0, slot: -1, hayOffset: 0, needleOffset: 0 };
  if (!Array.isArray(slots)) return out;
  for (let s = 0; s < slots.length; s++) {
    const r = longestRun(slots[s], needle);
    if (r.len > out.len) { out.len = r.len; out.slot = s; out.hayOffset = r.hayOffset; out.needleOffset = r.needleOffset; }
  }
  return out;
}

/** Hex string to bytes. Returns an empty array for anything that is not clean hex. */
export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    return new Uint8Array(0);
  }
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return b;
}

/**
 * A run length, graded.
 *
 * FULL means every byte of the tracer was found contiguously. PARTIAL means at
 * least `floor` of them were. NONE means less than that -- and NONE is a
 * statement about this window at this instant, never about secrecy. Read the
 * README section on what is outside the window before quoting a NONE.
 */
export function classify(len, needleLen, floor = PARTIAL_FLOOR) {
  if (!Number.isInteger(len) || !Number.isInteger(needleLen) || needleLen <= 0) {
    throw new TypeError('classify needs integer lengths and a positive needle length');
  }
  if (len >= needleLen) return 'FULL';
  if (len >= floor) return 'PARTIAL';
  return 'NONE';
}

/**
 * Is this tracer usable as a needle?
 *
 * The grading argument above assumes uniform random bytes. A tracer that
 * happened to contain a long run of one byte value would match the zeroed or
 * uninitialised parts of any stack, so such a draw is rejected and the runner
 * draws again. This has never fired in practice; it is here because the
 * alternative to checking is trusting /dev/urandom to never hand back a run,
 * and a measurement that fails that way fails silently.
 */
export function needleSanity(bytes, floor = PARTIAL_FLOOR) {
  const problems = [];
  if (!(bytes instanceof Uint8Array)) return { ok: false, problems: ['not a byte array'] };
  if (bytes.length < floor * 2) problems.push(`needle is ${bytes.length} bytes, shorter than twice the ${floor}-byte floor`);
  let run = 1;
  for (let i = 1; i < bytes.length; i++) {
    run = bytes[i] === bytes[i - 1] ? run + 1 : 1;
    if (run >= floor) { problems.push(`needle contains ${run} identical consecutive bytes`); break; }
  }
  // A needle that repeats a `floor`-byte block would make one hit look like two.
  const seen = new Set();
  for (let i = 0; i + floor <= bytes.length; i++) {
    const key = Array.from(bytes.slice(i, i + floor)).join(',');
    if (seen.has(key)) { problems.push(`needle repeats a ${floor}-byte block`); break; }
    seen.add(key);
  }
  return { ok: problems.length === 0, problems };
}

/**
 * Does the second implementation agree with the observer?
 *
 * Only the LENGTH is compared, not the offsets: the two searches scan in the
 * same order and would report the same first-best position, so comparing offsets
 * would add a coupling without adding a check.
 */
export function agrees(observerLen, ourLen) {
  return Number.isInteger(observerLen) && Number.isInteger(ourLen) && observerLen === ourLen;
}
