import { Router } from 'express';
import { requireDocumentRole } from '../access/require-document-role';
import { listDocuments, publishDocument, readDocument, writeDocument } from '../controllers/document-controller';

export const documentRouter = Router();

documentRouter.get('/', requireDocumentRole, listDocuments);
documentRouter.put('/:id', requireDocumentRole, writeDocument);
documentRouter.post('/:id/publish', requireDocumentRole, publishDocument);

documentRouter.get('/:id', readDocument);
