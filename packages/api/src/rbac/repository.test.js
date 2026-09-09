const fs = require('fs');
const os = require('os');
const path = require('path');
const { createRepository } = require('./index');
const { readRbacConfig } = require('./config');
const { mergePermissions, mergeResourceRules, normalizeRules } = require('./permissions');
const EnvRbacRepository = require('./EnvRbacRepository');
const { planEnvironmentImport } = require('./importEnvironment');

// Set RBAC_TEST_ENGINE/connection variables only to a disposable test database.
const engine = process.env.RBAC_TEST_ENGINE || 'sqlite';
let directory;
let repository;
let admin;
let config;

beforeAll(async () => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dbgate-rbac-test-'));
  config =
    engine === 'sqlite'
      ? {
          engine,
          filename: path.join(directory, 'rbac.sqlite'),
          bootstrapProvider: 'oauth',
          bootstrapLogin: 'Admin@example.com',
        }
      : {
          ...readRbacConfig({ ...process.env, RBAC_STORAGE_ENGINE: engine }),
          bootstrapProvider: 'oauth',
          bootstrapLogin: 'Admin@example.com',
        };
  repository = await createRepository(config);
  admin = await repository.getUserByExternalLogin(' ADMIN@example.com ', 'oauth');
}, 30000);

afterAll(async () => {
  if (repository) await repository.close();
  if (directory) fs.rmSync(directory, { recursive: true, force: true });
});

test('default configuration preserves env fallback and no-permission semantics', async () => {
  expect(readRbacConfig({})).toEqual({ engine: 'env' });
  const env = new EnvRbacRepository({ PERMISSIONS: '*', LOGIN_PERMISSIONS_alice: '~*', LOGIN_PERMISSIONS_bob: '' });
  expect(await env.getEffectivePermissions('alice')).toBe('~*');
  expect(await env.getEffectivePermissions('bob')).toBe('*');
  expect(await new EnvRbacRepository({}).getEffectivePermissions('alice')).toBeUndefined();
});

test('invalid backend and incomplete SQL settings fail rather than select another backend', () => {
  expect(() => readRbacConfig({ RBAC_STORAGE_ENGINE: 'oracle' })).toThrow('Invalid RBAC_STORAGE_ENGINE');
  expect(() =>
    readRbacConfig({ RBAC_STORAGE_ENGINE: 'postgres', RBAC_TOKEN_SECRET: 'test-secret-with-at-least-32-characters' })
  ).toThrow('Missing RBAC_STORAGE_SERVER');
  expect(() => readRbacConfig({ RBAC_STORAGE_ENGINE: 'mysql' })).toThrow('RBAC_TOKEN_SECRET');
  expect(() => readRbacConfig({ RBAC_STORAGE_ENGINE: 'sqlite', RBAC_STORAGE_FILE: 'relative.sqlite' })).toThrow(
    'absolute'
  );
  expect(() => readRbacConfig({ RBAC_STORAGE_ENGINE: 'sqlite', STORAGE_DATABASE: 'team' })).toThrow(
    'cannot be combined'
  );
});

test('bootstrap is idempotent and separates identity providers', async () => {
  expect(admin.login).toBe('admin@example.com');
  expect((await repository.getSnapshot(admin.id)).superadmin).toBe(true);
  expect(await repository.getUserByExternalLogin(admin.login, 'ad')).toBeNull();
  await repository.initialize();
  expect((await repository.inspect(admin.id)).users.filter(user => user.login === admin.login)).toHaveLength(1);
});

test('shared roles, direct rules, default deny, revision and rollback', async () => {
  const role = await repository.saveRole(admin.id, { name: 'analyst' });
  const user = await repository.saveUser(admin.id, { provider: 'oauth', login: 'alice', roleIds: [role.id] });
  expect(await repository.getEffectivePermissions(user.id)).toEqual(['~*']);
  await repository.replaceRules(admin.id, 'role', role.id, 'permissions', ['widgets/*', 'dbops/query']);
  await repository.replaceRules(admin.id, 'user', user.id, 'permissions', ['~widgets/admin']);
  expect(await repository.getEffectivePermissions(user.id)).toEqual([
    '~*',
    'widgets/*',
    'dbops/query',
    '~widgets/admin',
  ]);
  const version = await repository.getPermissionVersion(user.id);
  await expect(repository.replaceRules(user.id, 'role', role.id, 'permissions', ['*'])).rejects.toThrow(
    'superadmin required'
  );
  expect(await repository.getPermissionVersion(user.id)).toBe(version);
  await repository.replaceRules(admin.id, 'role', role.id, 'permissions', ['widgets/database']);
  expect(await repository.getPermissionVersion(user.id)).toBeGreaterThan(version);
  expect(await repository.getEffectivePermissions(user.id)).not.toContain('dbops/query');
  const before = await repository.inspect(admin.id);
  await expect(
    repository.saveUser(admin.id, { id: user.id, provider: 'oauth', login: 'changed', roleIds: ['missing'] })
  ).rejects.toMatchObject({ message: expect.any(String) });
  expect((await repository.getUserByExternalLogin('alice', 'oauth')).id).toBe(user.id);
  expect((await repository.inspect(admin.id)).audit).toHaveLength(before.audit.length);
  await repository.saveUser(admin.id, { id: user.id, provider: 'oauth', login: 'alice', enabled: false });
  await expect(repository.getSnapshot(user.id)).rejects.toThrow('disabled');
  await repository.deletePrincipal(admin.id, 'user', user.id);
  await expect(repository.getSnapshot(user.id)).rejects.toThrow('missing');
});

test('the last enabled superadmin cannot be disabled, demoted or deleted', async () => {
  await expect(repository.saveUser(admin.id, { ...admin, enabled: false, roleIds: ['superadmin'] })).rejects.toThrow(
    'At least one'
  );
  await expect(repository.saveUser(admin.id, { ...admin, enabled: true, roleIds: [] })).rejects.toThrow('At least one');
  await expect(repository.deletePrincipal(admin.id, 'user', admin.id)).rejects.toThrow('At least one');
  expect(() => repository.deletePrincipal(admin.id, 'role', 'superadmin')).toThrow('reserved');
  expect((await repository.getSnapshot(admin.id)).superadmin).toBe(true);
});

test('all resource kinds roundtrip and deny wins a tie across roles', async () => {
  const role = await repository.saveRole(admin.id, { name: 'resource-reader' });
  const user = await repository.saveUser(admin.id, { provider: 'oauth', login: 'reader', roleIds: [role.id] });
  const cases = {
    connections: [{ connection_conid: 'warehouse', effect: 'allow' }],
    databases: [{ connection_conid: 'warehouse', database_names_list: 'sales', database_permission_role_id: -2 }],
    tables: [
      {
        connection_conid: 'warehouse',
        table_names_list: 'invoices',
        table_permission_role_id: -1,
        table_permission_scope_id: -2,
      },
    ],
    files: [{ folder_name: 'sql', file_names_list: 'report.sql', file_permission_role_id: -1 }],
  };
  for (const [kind, rules] of Object.entries(cases))
    await repository.replaceRules(admin.id, 'role', role.id, kind, rules);
  await repository.replaceRules(admin.id, 'user', user.id, 'connections', [
    { connection_conid: 'warehouse', effect: 'deny' },
  ]);
  const snapshot = await repository.getSnapshot(user.id);
  expect(snapshot.connections.map(rule => rule.effect)).toEqual(['allow', 'deny']);
  expect(snapshot.permissions.slice(-2)).toEqual(['connections/warehouse', '~connections/warehouse']);
  for (const kind of ['databases', 'tables', 'files']) expect(snapshot[kind]).toEqual(cases[kind]);
  await repository.deletePrincipal(admin.id, 'role', role.id);
  expect((await repository.getSnapshot(user.id)).tables).toEqual([]);
});

test('SQL values are parameterized and invalid rule shapes cannot enter the database', async () => {
  const user = await repository.saveUser(admin.id, { provider: 'oauth', login: "x' OR 1=1 --" });
  expect((await repository.getUserByExternalLogin("x' OR 1=1 --", 'oauth')).id).toBe(user.id);
  expect(() => repository.replaceRules(admin.id, 'user', user.id, 'permissions', ['bad|permission'])).toThrow(
    'Invalid'
  );
  expect(() => normalizeRules('tables', [{ table_permission_role_id: -999 }])).toThrow('Invalid');
  expect(() => normalizeRules('databases', [{ database_permission_role_id: -1, database_names_regex: '[' }])).toThrow(
    'regular expression'
  );
  expect(() => normalizeRules('connections', [{ connection_conid: 'x', effect: 'allow', injected: 1 }])).toThrow(
    'Unknown'
  );
});

test('deterministic specificity and deny ordering does not depend on insertion order', () => {
  expect(mergePermissions(['~widgets/*', 'widgets/database', '*', '~widgets/database'])).toEqual([
    '~*',
    '*',
    '~widgets/*',
    'widgets/database',
    '~widgets/database',
  ]);
  const broad = { database_permission_role_id: -5 };
  const scoped = { connection_conid: 'x', database_names_list: 'sales', database_permission_role_id: -2 };
  const deny = { ...scoped, database_permission_role_id: -5 };
  expect(mergeResourceRules([deny, scoped, broad])).toEqual([broad, scoped, deny]);
});

test('concurrent edits are serialized and retain all audit records', async () => {
  const initial = await repository.getPermissionVersion(admin.id);
  await Promise.all(
    Array.from({ length: 5 }, (_, index) => repository.saveRole(admin.id, { name: `concurrent-${index}` }))
  );
  expect(await repository.getPermissionVersion(admin.id)).toBe(initial + 5);
});

test('SQLite persistence survives close/reopen and missing directory fails closed', async () => {
  if (engine !== 'sqlite') return;
  const second = await createRepository({ ...config, bootstrapLogin: undefined, bootstrapProvider: undefined });
  try {
    expect((await second.getSnapshot(admin.id)).superadmin).toBe(true);
  } finally {
    await second.close();
  }
  await expect(
    createRepository({ ...config, filename: path.join(directory, 'missing', 'rbac.sqlite') })
  ).rejects.toThrow();
});

test('environment import never stores passwords and rejects overwrites atomically', async () => {
  const plan = planEnvironmentImport(
    { LOGIN_PASSWORD_imported: 'secret-not-for-storage', LOGIN_PERMISSIONS_imported: 'widgets/*,~widgets/admin' },
    'oauth'
  );
  expect(JSON.stringify(plan)).not.toContain('secret-not-for-storage');
  await repository.importEnvironment(admin.id, plan);
  const imported = await repository.getUserByExternalLogin('imported', 'oauth');
  expect(await repository.getEffectivePermissions(imported.id)).toContain('~widgets/admin');
  await expect(
    repository.importEnvironment(admin.id, [
      { provider: 'oauth', login: 'rollback-import', permissions: ['*'] },
      ...plan,
    ])
  ).rejects.toThrow('refuses to overwrite');
  expect(await repository.getUserByExternalLogin('rollback-import', 'oauth')).toBeNull();
  expect(() => planEnvironmentImport({ LOGIN_PASSWORD_A: 'a', LOGIN_PASSWORD_a: 'b' }, 'oauth')).toThrow('collide');
});

test('SQLite connection enables foreign keys and WAL', async () => {
  if (engine !== 'sqlite') return;
  const flags = await repository.adapter.transaction(async query => ({
    foreignKeys: await query('PRAGMA foreign_keys'),
    journal: await query('PRAGMA journal_mode'),
  }));
  expect(flags.foreignKeys).toEqual([{ foreign_keys: 1 }]);
  expect(flags.journal).toEqual([{ journal_mode: 'wal' }]);
});

test('independent SQL pools serialize conflicting last-admin changes', async () => {
  if (engine === 'sqlite') return;
  const peer = await createRepository(config);
  try {
    const secondAdmin = await repository.saveUser(admin.id, {
      provider: 'oauth',
      login: 'second-admin',
      roleIds: ['superadmin'],
    });
    const results = await Promise.allSettled([
      repository.saveUser(admin.id, { id: admin.id, provider: 'oauth', login: admin.login, roleIds: [] }),
      peer.saveUser(secondAdmin.id, { id: secondAdmin.id, provider: 'oauth', login: 'second-admin', roleIds: [] }),
    ]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    const mainStillAdmin = (await repository.getSnapshot(admin.id)).superadmin;
    await repository.saveUser(mainStillAdmin ? admin.id : secondAdmin.id, {
      id: admin.id,
      provider: 'oauth',
      login: admin.login,
      roleIds: ['superadmin'],
    });
    await repository.deletePrincipal(admin.id, 'user', secondAdmin.id);
  } finally {
    await peer.close();
  }
});
