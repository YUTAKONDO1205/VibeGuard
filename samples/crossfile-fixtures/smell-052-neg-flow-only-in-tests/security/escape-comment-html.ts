// Exported, referenced by nothing, and there is no request data in this service
// for it to have been applied to.
export function escapeCommentHtml(raw: string): string {
  return raw.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
