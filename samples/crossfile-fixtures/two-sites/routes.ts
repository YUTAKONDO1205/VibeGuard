import { Router } from 'express';
import { archiveProject, listProjects } from './controllers/projects-controller';
import { inviteMember, listMembers } from './controllers/members-controller';

export const apiRouter = Router();

apiRouter.get('/projects', listProjects);
apiRouter.post('/projects/:id/archive', archiveProject);
apiRouter.get('/members', listMembers);
apiRouter.post('/members', inviteMember);
