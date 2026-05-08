const VAR_PATTERN = /\$\{([a-zA-Z_]\w*)\}/g;

export function interpolate(template: string, vars?: Record<string, unknown>): string {
  if (!vars) return template;
  return template.replace(VAR_PATTERN, (match, name: string) => {
    const value = vars[name];
    return value === undefined || value === null ? match : String(value);
  });
}
