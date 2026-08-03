// Minimal request/response shapes, declared locally so each fixture is one
// self-contained mini-project with no shared module to drift.
export interface SessionUser {
  id: string;
  role: string;
  permissions: string[];
  isAdmin: boolean;
  hasAccess(scope: string): boolean;
}

export interface AuthedRequest {
  user: SessionUser;
  params: Record<string, string>;
  body: Record<string, unknown>;
}
