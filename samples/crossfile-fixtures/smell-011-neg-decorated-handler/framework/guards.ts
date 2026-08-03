// A hand-rolled stand-in for the Nest / Spring style annotation. The rule reads
// the decorator NAME off the declaration; what the decorator does at runtime is
// beyond anything a lexical analysis can see, which is why the name is treated
// as the claim.
export function UseGuards(..._guards: unknown[]) {
  return function attach(_target: unknown, _key: string, descriptor: PropertyDescriptor) {
    return descriptor;
  };
}

export class OwnerGuard {
  canActivate(): boolean {
    return true;
  }
}
