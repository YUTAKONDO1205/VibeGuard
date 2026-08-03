import type { AuthedRequest } from '../types';

interface Turn {
  role: string;
  content: string;
}

const HISTORY: Record<string, Turn[]> = { t1: [{ role: 'user', content: 'hi' }] };

export async function listThreads(_req: AuthedRequest, res: any) {
  return res.json({ threads: Object.keys(HISTORY) });
}

export async function showThread(req: AuthedRequest, res: any) {
  return res.json({ turns: HISTORY[req.params.id] ?? [] });
}

export async function deleteThread(req: AuthedRequest, res: any) {
  delete HISTORY[req.params.id];
  return res.json({ deleted: true });
}

export async function appendTurn(req: AuthedRequest, res: any) {
  const history = HISTORY[req.params.id] ?? [];
  const last = history[history.length - 1];
  // A protocol rule about a conversation, wearing the same property name as a
  // privilege decision and refusing with the same status code.
  if (last && last.role === 'assistant') {
    return res.status(403).json({ error: 'the assistant cannot open a turn' });
  }
  history.push({ role: 'user', content: String(req.body.content) });
  return res.json({ turns: history.length });
}
