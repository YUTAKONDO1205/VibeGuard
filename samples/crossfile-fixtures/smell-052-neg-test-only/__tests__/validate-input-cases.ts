import { validateInput } from '../middleware/validate-input';

// The only reference to `validateInput` in this project. It is enough: something
// in the tree names the symbol, so "nobody could be calling it" is not a claim
// this analysis is entitled to make.
export function runValidateInputCases(): boolean {
  const calls: string[] = [];
  const res = {
    status(): typeof res {
      calls.push('status');
      return res;
    },
    json(): void {
      calls.push('json');
    },
  };
  validateInput(
    { params: { slug: 'not a slug!' } } as never,
    res as never,
    () => calls.push('next'),
  );
  return calls.join(',') === 'status,json';
}
