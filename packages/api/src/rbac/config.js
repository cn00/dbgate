const path = require('path');

function readRbacConfig(env = process.env) {
  const engine = env.RBAC_STORAGE_ENGINE || 'env';
  if (!['env', 'postgres', 'mysql', 'sqlite'].includes(engine)) {
    throw new Error('DBGM-00000 Invalid RBAC_STORAGE_ENGINE');
  }
  if (engine === 'env') return { engine };
  if (
    (env.RBAC_TOKEN_SECRET && env.RBAC_TOKEN_SECRET.length < 32) ||
    (['postgres', 'mysql'].includes(engine) && !env.RBAC_TOKEN_SECRET)
  ) {
    throw new Error('DBGM-00000 PG/MySQL RBAC requires a shared RBAC_TOKEN_SECRET of at least 32 characters');
  }
  if (env.STORAGE_DATABASE || env.SKIP_ALL_AUTH) {
    throw new Error('DBGM-00000 Dynamic RBAC cannot be combined with STORAGE_DATABASE or SKIP_ALL_AUTH');
  }
  const config = {
    engine,
    bootstrapLogin: env.RBAC_BOOTSTRAP_LOGIN,
    bootstrapProvider: env.RBAC_BOOTSTRAP_PROVIDER,
  };
  if (engine === 'sqlite') {
    if (!env.RBAC_STORAGE_FILE || !path.isAbsolute(env.RBAC_STORAGE_FILE)) {
      throw new Error('DBGM-00000 RBAC_STORAGE_FILE must be an absolute persistent file path');
    }
    return { ...config, filename: env.RBAC_STORAGE_FILE };
  }
  for (const key of ['SERVER', 'DATABASE', 'USER', 'PASSWORD']) {
    if (!env[`RBAC_STORAGE_${key}`]) throw new Error(`DBGM-00000 Missing RBAC_STORAGE_${key}`);
  }
  const port = Number(env.RBAC_STORAGE_PORT || (engine === 'postgres' ? 5432 : 3306));
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('DBGM-00000 Invalid RBAC_STORAGE_PORT');
  if (env.RBAC_STORAGE_SSL && !['true', 'false', '1', '0'].includes(env.RBAC_STORAGE_SSL)) {
    throw new Error('DBGM-00000 RBAC_STORAGE_SSL must be true or false');
  }
  return {
    ...config,
    host: env.RBAC_STORAGE_SERVER,
    port,
    database: env.RBAC_STORAGE_DATABASE,
    user: env.RBAC_STORAGE_USER,
    password: env.RBAC_STORAGE_PASSWORD,
    ssl: ['true', '1'].includes(env.RBAC_STORAGE_SSL) ? { rejectUnauthorized: true } : undefined,
  };
}

module.exports = { readRbacConfig };
