const { randomUUID } = require('crypto');
const { migrate, BUILTIN_ROLES } = require('./migrations');
const {
  KINDS,
  fail,
  normalizeLogin,
  validateProvider,
  normalizeRules,
  mergePermissions,
  mergeResourceRules,
} = require('./permissions');

class SqlRbacRepository {
  constructor(adapter, config = {}) {
    this.adapter = adapter;
    this.config = config;
  }

  async initialize() {
    await migrate(this.adapter);
    await this.adapter.transaction(
      async query => {
        await query('UPDATE rbac_revision SET version = version WHERE id = 1');
        const users = await query('SELECT id FROM rbac_users');
        if (!users.length) {
          const login = normalizeLogin(this.config.bootstrapLogin);
          const provider = validateProvider(this.config.bootstrapProvider);
          const id = randomUUID();
          await query('INSERT INTO rbac_users (id, provider, login, enabled) VALUES (?, ?, ?, 1)', [
            id,
            provider,
            login,
          ]);
          await query('INSERT INTO rbac_user_roles (user_id, role_id) VALUES (?, ?)', [id, 'superadmin']);
          await this.audit(query, 'bootstrap', 'bootstrap', { id, provider, login });
        }
        await this.requireAdmin(query);
      },
      { write: true }
    );
  }

  async requireAdmin(query) {
    const rows = await query(`SELECT u.id FROM rbac_users u JOIN rbac_user_roles ur ON ur.user_id = u.id
      WHERE ur.role_id = 'superadmin' AND u.enabled = 1`);
    if (!rows.length) fail('At least one enabled RBAC superadmin is required');
  }

  close() {
    return this.adapter.close();
  }

  getUserByExternalLogin(login, provider = this.config.bootstrapProvider) {
    login = normalizeLogin(login);
    validateProvider(provider);
    return this.adapter.transaction(
      async query =>
        (await query('SELECT * FROM rbac_users WHERE provider = ? AND login = ?', [provider, login]))[0] || null
    );
  }

  async snapshot(query, userId) {
    const [user] = await query('SELECT * FROM rbac_users WHERE id = ?', [userId]);
    if (!user || Number(user.enabled) !== 1) fail('RBAC user is missing or disabled');
    const roleRows = await query('SELECT role_id FROM rbac_user_roles WHERE user_id = ?', [userId]);
    const roles = [...new Set(['logged-user', ...roleRows.map(row => row.role_id)])];
    const superadmin = roles.includes('superadmin');
    const [revision] = await query('SELECT version FROM rbac_revision WHERE id = 1');
    const result = { user, roles, superadmin, version: Number(revision.version) };
    for (const kind of KINDS) {
      const userRules = await query(`SELECT * FROM rbac_user_${kind} WHERE user_id = ?`, [userId]);
      const roleRules = await query(
        `SELECT * FROM rbac_role_${kind} WHERE role_id IN (${roles.map(() => '?').join(',')})`,
        roles
      );
      const rows = [...userRules, ...roleRules];
      result[kind] =
        kind === 'permissions'
          ? superadmin
            ? ['*']
            : mergePermissions(rows.map(row => row.permission))
          : mergeResourceRules(
              normalizeRules(
                kind,
                rows.map(row => JSON.parse(row.rule))
              )
            );
    }
    // Expose resource connection grants in the legacy menu filter too.
    if (!superadmin)
      result.permissions = mergePermissions([
        ...result.permissions.slice(1),
        ...result.connections.map(rule => `${rule.effect === 'deny' ? '~' : ''}connections/${rule.connection_conid}`),
      ]);
    return result;
  }

  getSnapshot(userId) {
    return this.adapter.transaction(query => this.snapshot(query, userId));
  }
  async getEffectivePermissions(userId) {
    return (await this.getSnapshot(userId)).permissions;
  }
  async getConnectionPermissions(userId) {
    return (await this.getSnapshot(userId)).connections;
  }
  async getDatabasePermissions(userId) {
    return (await this.getSnapshot(userId)).databases;
  }
  async getTablePermissions(userId) {
    return (await this.getSnapshot(userId)).tables;
  }
  async getFilePermissions(userId) {
    return (await this.getSnapshot(userId)).files;
  }
  async getPermissionVersion(userId) {
    return (await this.getSnapshot(userId)).version;
  }

  async audit(query, actor, action, detail) {
    await query('INSERT INTO rbac_audit (id, actor, action, detail, created_at) VALUES (?, ?, ?, ?, ?)', [
      randomUUID(),
      actor,
      action,
      JSON.stringify(detail),
      new Date().toISOString(),
    ]);
    await query('UPDATE rbac_revision SET version = version + 1 WHERE id = 1');
  }

  async mutate(actorId, action, detail, change) {
    return this.adapter.transaction(
      async query => {
        // Serializes all policy edits across instances, including last-admin protection.
        await query('UPDATE rbac_revision SET version = version WHERE id = 1');
        const actor = await this.snapshot(query, actorId);
        if (!actor.superadmin) fail('RBAC superadmin required');
        const value = await change(query);
        await this.requireAdmin(query);
        await this.audit(query, actorId, action, detail);
        return value;
      },
      { write: true }
    );
  }

  saveUser(actorId, { id = randomUUID(), provider, login, enabled = true, roleIds = [] }) {
    validateProvider(provider);
    login = normalizeLogin(login);
    if (typeof enabled !== 'boolean' || !Array.isArray(roleIds) || roleIds.length > 100) fail('Invalid RBAC user');
    if (typeof id !== 'string' || !id || id.length > 36) fail('Invalid RBAC user ID');
    if (roleIds.some(role => typeof role !== 'string' || role.length > 36 || role === 'anonymous-user'))
      fail('Invalid RBAC role ID');
    return this.mutate(actorId, 'saveUser', { id, provider, login, enabled, roleIds }, async query => {
      const [existing] = await query('SELECT id FROM rbac_users WHERE id = ?', [id]);
      if (existing)
        await query('UPDATE rbac_users SET provider = ?, login = ?, enabled = ? WHERE id = ?', [
          provider,
          login,
          Number(enabled),
          id,
        ]);
      else
        await query('INSERT INTO rbac_users (id, provider, login, enabled) VALUES (?, ?, ?, ?)', [
          id,
          provider,
          login,
          Number(enabled),
        ]);
      await query('DELETE FROM rbac_user_roles WHERE user_id = ?', [id]);
      for (const roleId of new Set(roleIds))
        await query('INSERT INTO rbac_user_roles (user_id, role_id) VALUES (?, ?)', [id, roleId]);
      return { id };
    });
  }

  saveRole(actorId, { id = randomUUID(), name }) {
    if (typeof id !== 'string' || !id || id.length > 36 || BUILTIN_ROLES.includes(id))
      fail('Invalid or reserved RBAC role ID');
    if (typeof name !== 'string' || !name.trim() || name.length > 100 || BUILTIN_ROLES.includes(name))
      fail('Invalid or reserved RBAC role name');
    return this.mutate(actorId, 'saveRole', { id, name }, async query => {
      const [existing] = await query('SELECT id FROM rbac_roles WHERE id = ?', [id]);
      if (existing) await query('UPDATE rbac_roles SET name = ? WHERE id = ?', [name, id]);
      else await query('INSERT INTO rbac_roles (id, name) VALUES (?, ?)', [id, name]);
      return { id };
    });
  }

  deletePrincipal(actorId, owner, id) {
    if (typeof id !== 'string' || !id || id.length > 36) fail('Invalid RBAC principal ID');
    if (!['user', 'role'].includes(owner) || BUILTIN_ROLES.includes(id)) fail('Invalid or reserved RBAC principal');
    return this.mutate(actorId, 'deletePrincipal', { owner, id }, query =>
      query(`DELETE FROM rbac_${owner === 'user' ? 'users' : 'roles'} WHERE id = ?`, [id])
    );
  }

  replaceRules(actorId, owner, id, kind, input) {
    if (!['user', 'role'].includes(owner) || ['anonymous-user', 'superadmin'].includes(id))
      fail('Invalid or reserved RBAC principal');
    const rules = normalizeRules(kind, input);
    return this.mutate(actorId, 'replaceRules', { owner, id, kind, rules }, async query => {
      const [principal] = await query(`SELECT id FROM rbac_${owner === 'user' ? 'users' : 'roles'} WHERE id = ?`, [id]);
      if (!principal) fail('RBAC principal does not exist');
      await query(`DELETE FROM rbac_${owner}_${kind} WHERE ${owner}_id = ?`, [id]);
      for (const rule of rules)
        await query(
          `INSERT INTO rbac_${owner}_${kind} (id, ${owner}_id, ${
            kind === 'permissions' ? 'permission' : 'rule'
          }) VALUES (?, ?, ?)`,
          [randomUUID(), id, kind === 'permissions' ? rule : JSON.stringify(rule)]
        );
      return { count: rules.length };
    });
  }

  inspect(actorId) {
    return this.adapter.transaction(async query => {
      if (!(await this.snapshot(query, actorId)).superadmin) fail('RBAC superadmin required');
      const result = {};
      for (const table of [
        'users',
        'roles',
        'user_roles',
        ...['user', 'role'].flatMap(owner => KINDS.map(kind => `${owner}_${kind}`)),
      ]) {
        result[table] = await query(
          `SELECT * FROM rbac_${table} ORDER BY ${table === 'user_roles' ? 'user_id, role_id' : 'id'}`
        );
      }
      result.audit = await query('SELECT * FROM rbac_audit ORDER BY created_at DESC, id DESC LIMIT 100');
      return result;
    });
  }

  importEnvironment(actorId, plan) {
    return this.mutate(
      actorId,
      'importEnvironment',
      { users: plan.map(user => ({ provider: user.provider, login: user.login })) },
      async query => {
        for (const item of plan) {
          const provider = validateProvider(item.provider);
          const login = normalizeLogin(item.login);
          const permissions = normalizeRules('permissions', item.permissions);
          const [existing] = await query('SELECT id FROM rbac_users WHERE provider = ? AND login = ?', [
            provider,
            login,
          ]);
          if (existing) fail(`RBAC import refuses to overwrite existing user: ${login}`);
          const id = randomUUID();
          await query('INSERT INTO rbac_users (id, provider, login, enabled) VALUES (?, ?, ?, 1)', [
            id,
            provider,
            login,
          ]);
          for (const permission of permissions)
            await query('INSERT INTO rbac_user_permissions (id, user_id, permission) VALUES (?, ?, ?)', [
              randomUUID(),
              id,
              permission,
            ]);
        }
      }
    );
  }
}

module.exports = SqlRbacRepository;
