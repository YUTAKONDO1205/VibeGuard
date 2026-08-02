import { store } from '../storage/blob-store.js';
import type { Document } from '../models/document.js';

export async function saveDocument(document: Document, packed: string): Promise<void> {
  await store.put(document.id, packed);
}
