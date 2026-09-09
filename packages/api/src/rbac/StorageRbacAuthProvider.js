const jwt = require('jsonwebtoken');
const { AuthProviderBase } = require('../auth/authProvider');
const { getTokenSecret } = require('../auth/authCommon');
const { normalizeLogin, fail } = require('./permissions');

class StorageRbacAuthProvider extends AuthProviderBase {
  constructor(authentication, repository) {
    super();
    this.authentication = authentication;
    this.repository = repository;
    this.amoid = authentication.amoid;
    this.skipInList = authentication.skipInList;
  }

  getCurrentLogin(req) {
    const login = this.authentication.getCurrentLogin(req);
    return login == null ? null : normalizeLogin(login);
  }

  async getSnapshot(req) {
    if (!req) fail('RBAC request identity is required');
    if (!req.rbacSnapshot) {
      req.rbacSnapshot = (async () => {
        const login = this.getCurrentLogin(req);
        if (!login)
          return { permissions: ['~*'], connections: [], databases: [], tables: [], files: [], superadmin: false };
        const user = await this.repository.getUserByExternalLogin(login, this.amoid);
        if (!user) fail('RBAC user is not registered');
        if (req.user?.rbacUserId && req.user.rbacUserId !== user.id) fail('RBAC token identity no longer exists');
        return this.repository.getSnapshot(user.id);
      })();
    }
    return req.rbacSnapshot;
  }

  async assertCurrentUser(req) {
    const snapshot = await this.getSnapshot(req);
    if (!snapshot.user) fail('RBAC authenticated user is required');
    return snapshot;
  }

  async validateLoginResult(result) {
    if (!result?.accessToken) return result;
    const user = jwt.verify(result.accessToken, getTokenSecret());
    const snapshot = await this.assertCurrentUser({ user });
    return {
      ...result,
      accessToken: jwt.sign({ ...user, amoid: this.amoid, rbacUserId: snapshot.user.id }, getTokenSecret()),
    };
  }

  async login(...args) {
    try {
      return await this.validateLoginResult(await this.authentication.login(...args));
    } catch (_) {
      return { error: 'DBGM-00000 Login or RBAC authorization failed' };
    }
  }

  async oauthToken(...args) {
    try {
      return await this.validateLoginResult(await this.authentication.oauthToken(...args));
    } catch (_) {
      return { error: 'DBGM-00000 OAuth login or RBAC authorization failed' };
    }
  }

  async getCurrentPermissions(req) {
    return (await this.getSnapshot(req)).permissions;
  }
  async getCurrentDatabasePermissions(req) {
    return (await this.getSnapshot(req)).databases;
  }
  async getCurrentTablePermissions(req) {
    return (await this.getSnapshot(req)).tables;
  }
  async getCurrentFilePermissions(req) {
    return (await this.getSnapshot(req)).files;
  }
  async checkCurrentConnectionPermission(req, conid) {
    const { hasPermission } = require('../utility/hasPermission');
    const snapshot = await this.getSnapshot(req);
    return snapshot.superadmin || hasPermission(`connections/${conid}`, snapshot.permissions);
  }

  toJson() {
    return this.authentication.toJson();
  }
  redirect(...args) {
    return this.authentication.redirect(...args);
  }
  getLogoutUrl(...args) {
    return this.authentication.getLogoutUrl(...args);
  }
  getLoginPageConnections(...args) {
    return this.authentication.getLoginPageConnections(...args);
  }
  getSingleConnectionId(...args) {
    return this.authentication.getSingleConnectionId(...args);
  }
}

module.exports = StorageRbacAuthProvider;
