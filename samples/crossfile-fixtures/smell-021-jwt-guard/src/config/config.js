const config = {
  issuer: process.env.ISSUER || 'https://issuer.example',
  audience: process.env.AUDIENCE || 'api',
};

module.exports = { config };
