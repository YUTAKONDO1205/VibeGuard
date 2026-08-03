import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { addWidget, dropWidget, editWidget } from '../store';

export async function createWidget(req: AuthedRequest, res: Response) {
  const created = await addWidget(req.body);
  return res.status(201).json({ created });
}

export async function updateWidget(req: AuthedRequest, res: Response) {
  const updated = await editWidget(req.params.id, req.body.label);
  return res.json({ updated });
}

export async function removeWidget(req: AuthedRequest, res: Response) {
  await dropWidget(req.params.id);
  return res.status(204).end();
}

export async function duplicateWidget(req: AuthedRequest, res: Response) {
  const copy = await addWidget({ id: `${req.params.id}-copy`, label: req.body.label });
  return res.status(201).json({ copy });
}
