export interface Subject {
  id: string;
  permissions: string[];
}

/**
 * Template Method. `authorize` is meant to be supplied by every subclass; the
 * body exists only so that forgetting to supply it fails loudly at runtime.
 */
export class AbstractAuthorizer {
  authorize(subject: Subject): boolean {
    throw new Error('subclasses must implement authorize()');
  }

  describe(): string {
    return this.constructor.name;
  }
}
