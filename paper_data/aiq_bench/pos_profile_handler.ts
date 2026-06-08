import type { Request, Response } from "express";

export function getProfile(req: Request, res: Response) {
  const mockUser = { id: req.params.id, name: "Alice", plan: "pro" };
  return res.json(mockUser);
}
