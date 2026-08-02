import { verifyToken } from '../security/verify-token';

interface UpgradeRequest {
  headers: Record<string, string | undefined>;
}

interface Socket {
  destroy(): void;
}

// Not an Express route, and that is the point: the checkpoint runs here, on the
// upgrade handshake, where no `middlewareNames` list will ever mention it.
export function handleUpgrade(request: UpgradeRequest, socket: Socket): boolean {
  if (!verifyToken(request.headers.authorization)) {
    socket.destroy();
    return false;
  }
  return true;
}
