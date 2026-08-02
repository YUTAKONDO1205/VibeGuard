// NEGATIVE fixture: two view components in a cycle, one of them an auth form.
// A component holds no load-time security state — what a cycle costs here is a
// component that renders as `undefined`, which is a rendering defect and not the
// mechanism this rule names.
import { renderOtpForm } from './otp-form.js';

export function renderAuthForm(): string {
  return `<form>${renderOtpForm()}</form>`;
}

export function showLoginFailedToast(): string {
  return 'login failed';
}
