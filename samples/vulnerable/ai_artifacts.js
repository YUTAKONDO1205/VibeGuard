// Sample exhibiting "AI-generated boilerplate" tells. Each block targets one
// of the VG-QUAL-005..010 heuristic rules.

// VG-QUAL-008 — debug/verbose flags hardcoded ON
export const config = {
  debug: true,
  verbose: true,
};

// VG-QUAL-005 — stub body
export function deleteAccount(userId) {
  throw new Error("Not implemented");
}

// VG-QUAL-005 — return-with-TODO marker
export function getUserPermissions(userId) {
  return null; // TODO implement permission lookup
}

// VG-QUAL-006 — placeholder email left in source
export const SUPPORT_FROM = "noreply@example.com";
export const ADMIN_EMAIL = "admin@test.com";

// VG-QUAL-007 — mock data identifiers in production path
const mockUser = { id: 1, name: "Alice", role: "admin" };

export function currentUser() {
  return mockUser;
}

// VG-QUAL-009 — placeholder prose
// for now, just trust the request — replace this with real validation later
export function authenticate(req) {
  return true;
}

// VG-QUAL-010 — passthrough validator
export function validateInput(input) {
  return true;
}

export const sanitize = (x) => x;
