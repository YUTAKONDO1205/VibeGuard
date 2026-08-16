#!/usr/bin/env node
/**
 * Adapter: IrCheckpoints observation records -> fragility matrix cells.
 *
 * The records this reads are the ones run-matrix.sh writes, one JSON file per
 * cell, under the lab directory on the Linux side. Four of the five fields the
 * fragility matrix needs are carried in the record directly:
 *
 *   propertyId        <- record.propertyId
 *   state             <- record.verdict.state
 *   controlHeld       <- record.control.held
 *   completesTheCheck <- record.verdict.completesTheCheck
 *
 * The fifth is the problem, and it is worth stating plainly rather than hiding
 * in a default.
 *
 * ★ THE RECORDS CARRY NO CONFIGURATION. There is no `config`, no `invocation`,
 *   no optimisation level and no target anywhere in an IrCheckpoints record —
 *   measured across all 22 records in the lab, the top-level key set is
 *   identical in every one of them and contains none of those. The optimisation
 *   level survives only in the FILE NAME that run-matrix.sh chose (`erasure-O2`
 *   from `"erasure${O}"`), and the other three axes were never varied and are
 *   recorded nowhere at all.
 *
 * So this adapter derives `opt` from the cell id's suffix and says so in the
 * returned provenance, and it refuses — rather than defaulting — when a cell id
 * has no such suffix. A guessed optimisation level would put a cell in a column
 * of an envelope it was never measured in, and the envelope is the half of a
 * fragility score that stops it being over-read.
 *
 * `ndebug`, `lto` and `target` are reported as never recorded. They then show up
 * in the fragility report's `unmeasuredAxes`, which is the correct and honest
 * output: this matrix is a one-axis sweep, not a configuration envelope, and a
 * score computed from it must not be quoted as though it covered one.
 */

import { readdir, readFile } from 'node:fs/promises';
import { join, basename } from 'node:path';

/** Axes a full envelope would carry that an IrCheckpoints record never states. */
export const AXES_NOT_RECORDED = Object.freeze(['ndebug', 'lto', 'target']);

/** `-O0`, `-O2`, `-Os`, `-Ofast` at the end of a cell id. */
const OPT_SUFFIX = /-(O[0-9]|Os|Oz|Ofast)$/;

export class AdapterError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AdapterError';
    /** interfaces.md section 7: a check that could not be completed. */
    this.exitCode = 3;
  }
}

const path = (o, ...keys) => keys.reduce((acc, k) => (acc == null ? undefined : acc[k]), o);

/**
 * Convert one record to a matrix cell.
 *
 * @param {string} cellId the record's file name without `.json`
 * @param {object} record the parsed record
 */
export function adaptRecord(cellId, record) {
  if (typeof cellId !== 'string' || cellId.length === 0) {
    throw new AdapterError('a cell id is required and comes from the record file name');
  }
  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    throw new AdapterError(`${cellId}: the record is not a JSON object`);
  }

  const m = OPT_SUFFIX.exec(cellId);
  if (!m) {
    throw new AdapterError(
      `${cellId}: no optimisation level could be determined. The record does not carry one and ` +
        `the cell id does not end in a recognised -O suffix. This is refused rather than ` +
        `defaulted: a cell placed in a configuration it was not measured in makes the envelope ` +
        `wrong in the direction that reads as more coverage than there was.`,
    );
  }

  const state = path(record, 'verdict', 'state');
  const completesTheCheck = path(record, 'verdict', 'completesTheCheck');
  const controlHeld = path(record, 'control', 'held');
  const propertyId = record.propertyId;
  // The direction the states read in. Taken from the measurement rather than
  // inferred from the property id's prefix: `oracle.findingWhenPresent` is what
  // the observer was actually configured with, and a name-based guess here
  // would be the same class of mistake as a name-based effect oracle
  // (interfaces.md section 4).
  const findingWhenPresent = path(record, 'oracle', 'findingWhenPresent');

  for (const [name, value] of [
    ['propertyId', propertyId],
    ['verdict.state', state],
    ['verdict.completesTheCheck', completesTheCheck],
    ['control.held', controlHeld],
    ['oracle.findingWhenPresent', findingWhenPresent],
  ]) {
    if (value === undefined) {
      throw new AdapterError(
        `${cellId}: the record has no ${name}. A missing field is not filled in with the ` +
          `permissive reading; the record is reported as unusable instead.`,
      );
    }
  }

  if (typeof findingWhenPresent !== 'boolean') {
    throw new AdapterError(
      `${cellId}: oracle.findingWhenPresent is ${JSON.stringify(findingWhenPresent)}, not a ` +
        `boolean, so the property's polarity is unknown. Refused rather than assumed: guessing ` +
        `must-survive for a must-not-appear property scores its successes as failures.`,
    );
  }

  return {
    cellId,
    propertyId,
    polarity: findingWhenPresent ? 'must-not-appear' : 'must-survive',
    // Only the axis that was actually varied. The three that were not are left
    // absent rather than stated as a default, so the fragility report lists
    // them under `unmeasuredAxes` instead of showing a fabricated column.
    config: { opt: m[1] },
    state,
    controlHeld,
    completesTheCheck,
  };
}

/**
 * Convert a directory of records.
 *
 * @returns {{cells: object[], provenance: object}}
 */
export async function adaptRecordDirectory(dir) {
  let names;
  try {
    names = (await readdir(dir)).filter((n) => n.endsWith('.json')).sort();
  } catch (err) {
    throw new AdapterError(`could not read the records directory: ${err.message}`);
  }
  if (names.length === 0) {
    throw new AdapterError(
      `no records were found in the given directory. An empty read is reported, not returned as ` +
        `an empty matrix — a matrix of zero cells scored 0.000 is the failure this component ` +
        `exists to make impossible.`,
    );
  }

  const cells = [];
  for (const name of names) {
    const raw = await readFile(join(dir, name), 'utf8');
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new AdapterError(`${name}: not JSON (${err.message})`);
    }
    cells.push(adaptRecord(basename(name, '.json'), parsed));
  }

  return {
    cells,
    provenance: {
      source: 'IrCheckpoints observation records',
      recordCount: cells.length,
      // Named so that nobody reading the resulting envelope believes the
      // optimisation level came out of the measurement.
      optDerivedFrom: 'cell-id-suffix, because the record carries no configuration',
      axesNeverRecorded: [...AXES_NOT_RECORDED],
    },
  };
}

// --- CLI --------------------------------------------------------------------

const USAGE = `usage: node adapt-ir-checkpoints.mjs <records-dir>

Writes a fragility matrix to stdout: {"provenance": {...}, "cells": [...]}.
Pipe it to a file and score it with fragility.mjs.

exit codes: 0 converted, 3 nothing convertible (interfaces.md section 7)`;

if (process.argv[1] && /(^|[/\\])adapt-ir-checkpoints\.mjs$/.test(process.argv[1].replace(/\\/g, '/'))) {
  const dir = process.argv[2];
  if (!dir || dir === '-h' || dir === '--help') {
    process.stdout.write(USAGE + '\n');
    process.exitCode = dir ? 0 : 3;
  } else {
    adaptRecordDirectory(dir)
      .then((out) => {
        process.stdout.write(JSON.stringify(out, null, 2) + '\n');
      })
      .catch((err) => {
        process.stderr.write(`${err.message}\n`);
        process.exitCode = err instanceof AdapterError ? err.exitCode : 3;
      });
  }
}
