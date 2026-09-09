const { readRbacConfig } = require('./config');
const { createAdapter } = require('./adapters');
const EnvRbacRepository = require('./EnvRbacRepository');
const SqlRbacRepository = require('./SqlRbacRepository');

let repository;

function isDynamicRbac() {
  return !!process.env.RBAC_STORAGE_ENGINE && process.env.RBAC_STORAGE_ENGINE !== 'env';
}

async function createRepository(config = readRbacConfig()) {
  if (!['env', 'postgres', 'mysql', 'sqlite'].includes(config.engine)) {
    throw new Error('DBGM-00000 Invalid RBAC storage engine');
  }
  if (config.engine === 'env') return new EnvRbacRepository();
  const adapter = await createAdapter(config);
  const result = new SqlRbacRepository(adapter, config);
  try {
    await result.initialize();
    return result;
  } catch (err) {
    await result.close().catch(() => {});
    throw err;
  }
}

async function initializeRbac() {
  const config = readRbacConfig();
  if (config.engine === 'env') return;
  const { getAuthProviders, getDefaultAuthProvider, setAuthProviders } = require('../auth/authProvider');
  const providers = getAuthProviders();
  if (providers.some(provider => !['oauth', 'ad', 'logins'].includes(provider.amoid))) {
    throw new Error('DBGM-00000 Dynamic RBAC requires OAuth, AD or configured logins');
  }
  if (providers.some(provider => provider.amoid === 'oauth') && !process.env.OAUTH_LOGIN_FIELD) {
    throw new Error('DBGM-00000 Dynamic OAuth RBAC requires OAUTH_LOGIN_FIELD');
  }
  if (config.bootstrapProvider && !providers.some(provider => provider.amoid === config.bootstrapProvider)) {
    throw new Error('DBGM-00000 RBAC bootstrap provider must match an enabled authentication provider');
  }
  repository = await createRepository(config);
  const StorageRbacAuthProvider = require('./StorageRbacAuthProvider');
  const defaultId = getDefaultAuthProvider().amoid;
  const wrapped = providers.map(provider => new StorageRbacAuthProvider(provider, repository));
  setAuthProviders(
    wrapped,
    wrapped.find(provider => provider.amoid === defaultId)
  );
}

function getRepository() {
  if (!repository) throw new Error('DBGM-00000 RBAC storage is not initialized');
  return repository;
}

module.exports = { createRepository, initializeRbac, getRepository, isDynamicRbac };
