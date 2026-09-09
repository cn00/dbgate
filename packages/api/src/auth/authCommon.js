const crypto = require('crypto');

const tokenSecret = crypto.randomUUID();

function getTokenLifetime() {
  return process.env.TOKEN_LIFETIME || '1d';
}

function getTokenSecret() {
  if (process.env.RBAC_STORAGE_ENGINE && process.env.RBAC_STORAGE_ENGINE !== 'env' && process.env.RBAC_TOKEN_SECRET) {
    return process.env.RBAC_TOKEN_SECRET;
  }
  return tokenSecret;
}

function getStaticTokenSecret() {
  // TODO static not fixed
  return '14813c43-a91b-4ad1-9dcd-a81bd7dbb05f';
}

module.exports = {
  getTokenLifetime,
  getTokenSecret,
  getStaticTokenSecret,
};
