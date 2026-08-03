import { Router } from 'express';
import { requireLogin } from '../middleware/require-login';
import { createNote, removeNote, shareNote, updateNote } from '../controllers/note-controller';

export const noteRouter = Router();

noteRouter.post('/notes', requireLogin, createNote);
noteRouter.put('/notes/:id', requireLogin, updateNote);
noteRouter.delete('/notes/:id', requireLogin, removeNote);

// Adds a recipient to somebody else's note, anonymously.
noteRouter.post('/notes/:id/share', shareNote);
