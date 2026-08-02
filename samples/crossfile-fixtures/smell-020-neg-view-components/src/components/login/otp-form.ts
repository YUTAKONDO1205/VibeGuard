import { showLoginFailedToast } from './auth-form.js';

export function renderOtpForm(): string {
  return '<input name="otp" />';
}

export function onOtpRejected(): string {
  return showLoginFailedToast();
}
