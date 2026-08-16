// FALSE-POSITIVE CONTROL, and the sharper of the two.
//
// `pages/index.tsx` sits at the top of the tree, where a predicate that walked
// segments looking for `pages` followed by `api` runs out of segments before it
// can be wrong. This one is NESTED, so a predicate loosened to "anything under
// pages/" would match it — and then every page component in every Next.js
// project becomes a route handler that VG-SMELL-010/011/013 read.
//
// It default-exports a function, exactly as an endpoint does. The ONLY thing
// separating it from `pages/api/reports.ts` is the `api` directory segment.

export default function SettingsPage() {
  return null;
}
