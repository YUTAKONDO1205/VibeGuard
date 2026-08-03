import { BarrelExportPolicy } from './policies/barrel-export-policy.js';
import { VendorExportPolicy } from './policies/vendor-export-policy.js';

export const policies = {
  barrel: new BarrelExportPolicy(),
  vendor: new VendorExportPolicy(),
};
