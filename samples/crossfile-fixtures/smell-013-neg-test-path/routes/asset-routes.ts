import { Router } from 'express';
import { requireAssetPolicy } from '../access/require-asset-policy';
import { deleteAsset, listAssets, uploadAsset } from '../controllers/asset-controller';

export const assetRouter = Router();

assetRouter.get('/', requireAssetPolicy, listAssets);
assetRouter.post('/', requireAssetPolicy, uploadAsset);
assetRouter.delete('/:id', requireAssetPolicy, deleteAsset);
