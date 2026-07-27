import { Router } from 'express';

const devices: Array<{ id: string; label: string }> = [];

export const deviceRouter = Router();

// Site 3 of three, in a second file so the two-file condition is satisfied.
deviceRouter.get('/', (req, res) => {
  const member = req.body.actor;
  if (member.role !== 'editor') {
    return res.status(403).send();
  }
  return res.json({ devices: devices.slice() });
});
