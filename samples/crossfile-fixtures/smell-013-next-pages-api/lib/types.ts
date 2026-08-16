// Minimal stand-ins for the framework types, so the fixture resolves without a
// dependency on Next.js itself. Nothing here is analysed: an interface carries
// no body for a rule to read.

export interface SessionUser {
  id: string;
  role: string;
}

export interface NextApiRequest {
  method: string;
  query: Record<string, string>;
  session: { user: SessionUser };
}

export interface NextApiResponse {
  status(code: number): NextApiResponse;
  json(body: unknown): void;
}

export type NextApiHandler = (req: NextApiRequest, res: NextApiResponse) => Promise<unknown> | unknown;
