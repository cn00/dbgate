const { normalizeLogin, validateProvider, normalizeRules } = require('./permissions');

// Dry-run output contains identity and permission rules only, never passwords or OAuth tokens.
function planEnvironmentImport(env, provider) {
  validateProvider(provider);
  const logins = new Set(env.LOGIN ? [env.LOGIN] : []);
  for (const key of Object.keys(env)) {
    for (const prefix of ['LOGIN_PERMISSIONS_', 'LOGIN_PASSWORD_']) {
      if (key.startsWith(prefix)) logins.add(key.substring(prefix.length));
    }
  }
  const seen = new Set();
  return [...logins].map(originalLogin => {
    const login = normalizeLogin(originalLogin);
    if (seen.has(login)) throw new Error('DBGM-00000 Environment logins collide after normalization');
    seen.add(login);
    const original = env[`LOGIN_PERMISSIONS_${originalLogin}`] || env.PERMISSIONS;
    return {
      provider,
      login,
      permissions: normalizeRules('permissions', original ? original.split(/,|;|\||\s/).filter(Boolean) : ['*']),
    };
  });
}

module.exports = { planEnvironmentImport };
