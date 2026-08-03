import { Router } from 'express';
import { requireProjectRole } from '../access/require-project-role';
import { archiveProject, createProject, listProjects } from '../controllers/project-controller';
import { addLabel, listLabels } from '../controllers/label-controller';
import { removeLabel } from '../controllers/tag-controller';

export const projectRouter = Router();

projectRouter.get('/', requireProjectRole, listProjects);
projectRouter.post('/', requireProjectRole, createProject);
projectRouter.post('/:id/archive', requireProjectRole, archiveProject);

projectRouter.get('/labels', listLabels);
projectRouter.post('/labels', addLabel);
projectRouter.delete('/labels/:id', removeLabel);
