import { Router } from 'express';
import { requireTeamRole } from '../access/require-team-role';
import { inviteMember, listMembers, removeMember, teamSummary } from '../controllers/team-controller';

export const teamRouter = Router();

teamRouter.get('/members', requireTeamRole('admin'), listMembers);
teamRouter.post('/members', requireTeamRole('admin'), inviteMember);
teamRouter.delete('/members/:id', requireTeamRole('admin'), removeMember);

// The endpoint that opted out of the convention. Reading this file, /summary
// looks like an endpoint that needs no privilege at all.
teamRouter.get('/summary', teamSummary);
