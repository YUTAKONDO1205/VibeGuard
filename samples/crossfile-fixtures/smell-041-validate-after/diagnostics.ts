// VG-SMELL-041 POSITIVE — the INVERTED ordering, with a VALIDATOR.
//
// A validator returns a verdict rather than a safe copy, so the only thing that
// can make it effective is that it runs FIRST. Here it runs after the command
// has already been executed, which is the purest form of the smell: the check
// is present, correct, and cannot have protected anything.
//
// The fixture also pins the rule's most important negative condition. The
// `res.send(output)` on the last line is a SECOND taint sink fed by the same
// source, and by the time it runs the hostname HAS been validated and the bad
// path has returned — so the rule must NOT report it. One finding, not two.
import childProcess from 'node:child_process';
import { isValidHostname } from './security/hostname';

export function pingHost(req: any, res: any) {
  const host = req.body.host;
  const command = `ping -c 1 ${host}`;
  const output = childProcess.execSync(command).toString();
  // The check the author wrote — after the command has already run.
  if (!isValidHostname(host)) {
    return res.status(400).send();
  }
  return res.send(output);
}
