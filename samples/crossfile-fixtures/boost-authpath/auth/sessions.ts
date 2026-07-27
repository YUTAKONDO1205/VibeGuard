import { Router } from 'express';

const sessions: Array<{ id: string; owner: string }> = [];

export const sessionRouter = Router();

// Sites 1 and 2 of three, and note the SHAPE: the handlers are written inline at
// the registration rather than exported by name. That is not decoration — see
// README.md. An exported symbol in a file whose path carries a security word is
// judged a GUARD by `symbol-table-builder`, and guards are excluded from this
// rule's population, so the named-export shape used by every other fixture
// produces zero sites here no matter what the boost does.
//
// The compared value is `editor`, never `admin`, so the privilege-word boost
// stays out of it, and neither handler writes anything.
sessionRouter.get('/', (req, res) => {
  const member = req.body.actor;
  if (member.role !== 'editor') {
    return res.status(403).send();
  }
  return res.json({ sessions: sessions.slice() });
});

sessionRouter.get('/:id', (req, res) => {
  const member = req.body.actor;
  if (member.role !== 'editor') {
    return res.status(403).send();
  }
  const found = sessions.find((s) => s.id === req.params.id);
  return found ? res.json(found) : res.status(404).send();
});
