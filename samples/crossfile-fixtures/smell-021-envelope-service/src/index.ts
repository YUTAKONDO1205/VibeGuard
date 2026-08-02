import { storeDocument, readDocument } from './api/documents.js';
import { exportRows } from './api/exports.js';

export const handlers = { storeDocument, readDocument, exportRows };
