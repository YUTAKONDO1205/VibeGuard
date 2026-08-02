import { listDocuments } from '../services/list-documents.js';

export const documentRoutes = {
  path: '/document',
  handlers: {
    async list(): Promise<unknown> {
      return listDocuments();
    },
  },
};
