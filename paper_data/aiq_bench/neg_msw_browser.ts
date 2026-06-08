import { setupWorker } from "msw/browser";
import { handlers } from "./handlers";

// Service worker that intercepts API calls during local development only.
export const mockWorker = setupWorker(...handlers);

if (import.meta.env.DEV) {
  mockWorker.start({ onUnhandledRequest: "bypass" });
}
