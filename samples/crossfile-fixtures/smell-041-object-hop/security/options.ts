// A validator that takes the whole options object and checks ONE field of it.
// Its argument is a bare mention of the chain name, which is what makes half one
// of the fixture reachable: the premise is satisfied, and the sink's own
// property access is the only thing keeping the file quiet.
import type { CliOptions } from '../args';

const SEMVER = /^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$/;

export function validateOptions(options: CliOptions): void {
  if (!SEMVER.test(options.version)) throw new Error('version must be semver');
}
