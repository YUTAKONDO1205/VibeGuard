// NEGATIVE fixture: a TYPE imported without the `type` keyword.
//
// `SessionShape` is declared with `export type` in `../app/context.js`, so
// TypeScript erases this import — it is never used in a value position. The
// import STATEMENT is indistinguishable from a value import, which is why the
// question has to be asked of the file being imported. See `ExportKinds`.
import { SessionShape } from '../app/context.js';

export function verifyPassword(state: SessionShape, secret: string): boolean {
  return state.secret === secret;
}
