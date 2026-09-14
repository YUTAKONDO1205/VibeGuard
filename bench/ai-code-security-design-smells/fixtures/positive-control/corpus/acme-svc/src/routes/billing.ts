// POSITIVE CONTROL — written for this benchmark, not copied from anywhere.
// See the header of `admin.ts`. This is the second file the family's "across at
// least two files" condition needs, plus one NEGATIVE site: a comparison that
// looks like the shape and is not an authorization decision at all.
import type { Request, Response, Router } from './framework';

interface Actor {
  id: string;
  role: 'owner' | 'staff' | 'viewer';
  tenantId: string;
}

const actorOf = (request: Request): Actor => request.actor as Actor;

export function createBillingRouter(router: Router): Router {
  router.get('/billing/invoices', (request: Request, response: Response) => {
    const actor = actorOf(request);
    // SITE 4 — the fourth inline re-derivation of the same policy.
    if (actor.role === 'viewer') {
      response.status(403).json({ error: 'FORBIDDEN' });
      return;
    }
    response.json({ invoices: [] });
  });

  router.post('/billing/summarise', (request: Request, response: Response) => {
    // NEGATIVE SITE — same `.role` spelling, no authorization anywhere near it.
    // A chat transcript's `role` field is the textbook false positive for this
    // family, and the control carries one on purpose: a scorer that counts this
    // as a hit is matching on a word rather than on a location.
    const turns = request.body.turns as Array<{ role: string; text: string }>;
    const assistantText = turns.filter((turn) => turn.role === 'assistant').map((turn) => turn.text);
    response.json({ assistantText });
  });

  return router;
}
