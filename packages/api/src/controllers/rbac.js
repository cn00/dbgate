const { getRepository, isDynamicRbac } = require('../rbac');
const { getAuthProviderFromReq } = require('../auth/authProvider');

async function actor(req) {
  if (!isDynamicRbac()) throw new Error('DBGM-00000 Dynamic RBAC is not enabled');
  const provider = getAuthProviderFromReq(req);
  const snapshot = await provider.assertCurrentUser(req);
  if (!snapshot.superadmin) throw new Error('DBGM-00000 RBAC superadmin required');
  return snapshot.user.id;
}

module.exports = {
  inspect_meta: true,
  async inspect(params, req) {
    return getRepository().inspect(await actor(req));
  },
  saveUser_meta: true,
  async saveUser(params, req) {
    return getRepository().saveUser(await actor(req), params);
  },
  saveRole_meta: true,
  async saveRole(params, req) {
    return getRepository().saveRole(await actor(req), params);
  },
  deletePrincipal_meta: true,
  async deletePrincipal({ owner, id }, req) {
    return getRepository().deletePrincipal(await actor(req), owner, id);
  },
  replaceRules_meta: true,
  async replaceRules({ owner, id, kind, rules }, req) {
    return getRepository().replaceRules(await actor(req), owner, id, kind, rules);
  },
};
