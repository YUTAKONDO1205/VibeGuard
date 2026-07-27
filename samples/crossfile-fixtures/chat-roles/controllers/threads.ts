import type { Request, Response } from 'express';

export function renderThread(req: Request, res: Response) {
  const rendered = req.body.messages.map((m: { role: string; content: string }) =>
    m.role === 'assistant' ? `AI: ${m.content}` : `You: ${m.content}`,
  );
  return res.json({ rendered });
}

export function summarise(req: Request, res: Response) {
  const msg = req.body.last;
  if (msg.role === 'system') return res.json({ skip: true });
  return res.json({ text: msg.content });
}
