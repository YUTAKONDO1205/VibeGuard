// The validator the handler calls too late.
//
// Every quantifier is bounded and the character class is explicit, so this
// fixture cannot become the reason a scan of the corpus gets slow.
const HOSTNAME = /^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$/;

export function isValidHostname(value: string): boolean {
  return HOSTNAME.test(value);
}
