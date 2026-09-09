jest.mock('dbgate-tools', () => ({ getLogger: () => ({ info() {}, error() {} }), extractErrorLogData: () => ({}) }), {
  virtual: true,
});
jest.mock('activedirectory2', () => ({ promiseWrapper: jest.fn() }));
jest.mock('../utility/crypting', () => ({}));
jest.mock('../utility/cloudIntf', () => ({}));
jest.mock('../utility/socket', () => ({}));
jest.mock('../utility/auditlog', () => ({}));
jest.mock('../utility/loginchecker', () => ({ markUserAsActive() {} }));
jest.mock('../utility/mcpAuth', () => ({}));

const jwt = require('jsonwebtoken');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { getTokenSecret } = require('../auth/authCommon');
const { AuthProviderBase, setAuthProviders, getAuthProviders } = require('../auth/authProvider');
const { authMiddleware } = require('../controllers/auth');
const { createRepository } = require('./index');
const StorageRbacAuthProvider = require('./StorageRbacAuthProvider');

let directory;
let repository;
let admin;
let provider;
const originalEngine = process.env.RBAC_STORAGE_ENGINE;
const originalProviders = getAuthProviders();

beforeAll(async () => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'dbgate-rbac-auth-'));
  repository = await createRepository({
    engine: 'sqlite',
    filename: path.join(directory, 'rbac.sqlite'),
    bootstrapProvider: 'oauth',
    bootstrapLogin: 'admin',
  });
  admin = await repository.getUserByExternalLogin('admin', 'oauth');
  const authentication = new AuthProviderBase();
  authentication.amoid = 'oauth';
  authentication.oauthToken = async ({ login }) => ({
    accessToken: jwt.sign({ login, amoid: 'oauth' }, getTokenSecret(), { expiresIn: '1h' }),
  });
  provider = new StorageRbacAuthProvider(authentication, repository);
  setAuthProviders([provider]);
  process.env.RBAC_STORAGE_ENGINE = 'sqlite';
});

afterAll(async () => {
  await repository?.close();
  if (directory) fs.rmSync(directory, { recursive: true, force: true });
  setAuthProviders(originalProviders);
  if (originalEngine == null) delete process.env.RBAC_STORAGE_ENGINE;
  else process.env.RBAC_STORAGE_ENGINE = originalEngine;
});

test('OAuth token contains stable user ID without roles or permissions', async () => {
  const result = await provider.oauthToken({ login: ' ADMIN ' });
  const token = jwt.verify(result.accessToken, getTokenSecret());
  expect(token.rbacUserId).toBe(admin.id);
  expect(token.amoid).toBe('oauth');
  expect(token.exp - token.iat).toBe(3600);
  expect(token.permissions).toBeUndefined();
  expect(token.roles).toBeUndefined();
});

test('unknown OAuth user receives no token; anonymous request is default-deny', async () => {
  expect((await provider.oauthToken({ login: 'unknown' })).accessToken).toBeUndefined();
  expect(await provider.getCurrentPermissions({})).toEqual(['~*']);
  await expect(provider.assertCurrentUser({})).rejects.toThrow('authenticated');
});

test('request snapshot is consistent and new requests immediately see role changes', async () => {
  const user = await repository.saveUser(admin.id, { provider: 'oauth', login: 'reader' });
  const req = { user: { login: 'reader', amoid: 'oauth', rbacUserId: user.id } };
  expect(await provider.getCurrentPermissions(req)).toEqual(['~*']);
  await repository.replaceRules(admin.id, 'user', user.id, 'permissions', ['widgets/database']);
  expect(await provider.getCurrentPermissions(req)).toEqual(['~*']);
  expect(await provider.getCurrentPermissions({ user: req.user })).toContain('widgets/database');
  await repository.saveUser(admin.id, { ...user, provider: 'oauth', login: 'reader', enabled: false });
  await expect(provider.assertCurrentUser({ user: req.user })).rejects.toThrow('disabled');
  expect((await provider.oauthToken({ login: 'reader' })).accessToken).toBeUndefined();
});

test('a deleted and recreated login cannot reuse its old token', async () => {
  const first = await repository.saveUser(admin.id, { provider: 'oauth', login: 'recreated' });
  await repository.deletePrincipal(admin.id, 'user', first.id);
  await repository.saveUser(admin.id, { provider: 'oauth', login: 'recreated' });
  await expect(provider.assertCurrentUser({ user: { login: 'recreated', rbacUserId: first.id } })).rejects.toThrow(
    'no longer exists'
  );
});

test('HTTP middleware rejects disabled, legacy and unknown-provider tokens', async () => {
  const user = await repository.saveUser(admin.id, { provider: 'oauth', login: 'middleware' });
  const { accessToken } = await provider.oauthToken({ login: 'middleware' });
  const send = async token => {
    const req = { path: '/connections/list', headers: { authorization: `Bearer ${token}` } };
    const res = { status: jest.fn().mockReturnThis(), send: jest.fn() };
    const next = jest.fn();
    await authMiddleware(req, res, next);
    return { res, next };
  };
  expect((await send(accessToken)).next).toHaveBeenCalledTimes(1);
  await repository.saveUser(admin.id, { id: user.id, provider: 'oauth', login: 'middleware', enabled: false });
  const disabled = await send(accessToken);
  expect(disabled.res.status).toHaveBeenCalledWith(401);
  expect(disabled.next).not.toHaveBeenCalled();
  const legacy = jwt.sign({ login: 'admin', amoid: 'oauth' }, getTokenSecret());
  expect((await send(legacy)).res.status).toHaveBeenCalledWith(401);
  const unknown = jwt.sign({ login: 'admin', amoid: 'unknown', rbacUserId: admin.id }, getTokenSecret());
  expect((await send(unknown)).res.status).toHaveBeenCalledWith(401);
});

test('MCP fails closed until its separate RBAC identity mapping is implemented', async () => {
  const res = { status: jest.fn().mockReturnThis(), send: jest.fn() };
  const next = jest.fn();
  await authMiddleware({ path: '/mcp', headers: {} }, res, next);
  expect(res.status).toHaveBeenCalledWith(403);
  expect(next).not.toHaveBeenCalled();
});
