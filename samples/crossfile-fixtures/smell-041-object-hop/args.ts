// The accumulator that makes the shape possible: one object, several unrelated
// fields, all of them read from the same tainted source.
export interface CliOptions {
  changelogFile: string;
  outFile: string;
  name: string;
  version: string;
}

export function parseArgs(argv: string[]): CliOptions {
  const [changelogFile = '', outFile = '', name = '', version = ''] = argv;
  return { changelogFile, outFile, name, version };
}
