// Feature flags resolved at build time. Beta is fully launched, so the gate
// is intentionally a constant until the flag is removed in the next release.
const checkBetaEnabled = () => true;

module.exports = { checkBetaEnabled };
