// POSITIVE CONTROL — written for this benchmark, not copied from anywhere.
//
// This file and its sibling `billing.ts` are a deliberate, minimal instance of
// the `inline-authorization` family: the same role decision is re-derived in
// four handler bodies across two files, and no shared guard takes it once. The
// ground truth is therefore BY CONSTRUCTION rather than by anyone's judgement —
// which is what makes it usable as a control. If the scorer cannot recover a
// finding here, the scorer is broken; there is no second reading available.
//
// Nothing in here is meant to be good code. It is meant to be an instance.
import type { Request, Response, Router } from './framework';

interface Actor {
  id: string;
  role: 'owner' | 'staff' | 'viewer';
  tenantId: string;
}

const actorOf = (request: Request): Actor => request.actor as Actor;

export function createAdminRouter(router: Router): Router {
  router.get('/admin/members', (request: Request, response: Response) => {
    const actor = actorOf(request);
    // SITE 1 — inline authorization decision in a handler body.
    if (actor.role !== 'owner' && actor.role !== 'staff') {
      response.status(403).json({ error: 'FORBIDDEN' });
      return;
    }
    response.json({ members: [] });
  });

  router.post('/admin/members', (request: Request, response: Response) => {
    const actor = actorOf(request);
    // SITE 2 — the same decision, re-derived, with a different threshold.
    if (actor.role !== 'owner') {
      response.status(403).json({ error: 'FORBIDDEN' });
      return;
    }
    response.status(201).json({ created: true });
  });

  router.delete('/admin/members/:id', (request: Request, response: Response) => {
    const actor = actorOf(request);
    // SITE 3 — and again, now also scoped by tenant.
    if (actor.role !== 'owner' || request.params.tenantId !== actor.tenantId) {
      response.status(403).json({ error: 'FORBIDDEN' });
      return;
    }
    response.json({ deleted: true });
  });

  return router;
}
