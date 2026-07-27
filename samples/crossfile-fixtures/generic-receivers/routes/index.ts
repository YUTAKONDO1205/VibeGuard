import { Router } from 'express';
import { auditMembers, promoteMember } from '../controllers/members';
import { archiveTeam } from '../controllers/teams';

export const router = Router();

router.get('/members/audit', auditMembers);
router.post('/members/promote', promoteMember);
router.post('/teams/archive', archiveTeam);
