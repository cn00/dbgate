const mockMysqlQuery = jest.fn();
const mockMysqlRelease = jest.fn();
const mockMysqlEnd = jest.fn();
const mockMysqlGetConnection = jest.fn(async () => ({ query: mockMysqlQuery, release: mockMysqlRelease }));
jest.mock('mysql2', () => ({
  createPool: jest.fn(() => ({ promise: () => ({ getConnection: mockMysqlGetConnection, end: mockMysqlEnd }) })),
}));
const mockPgQuery = jest.fn();
const mockPgRelease = jest.fn();
const mockPgEnd = jest.fn();
const mockPgConnect = jest.fn(async () => ({ query: mockPgQuery, release: mockPgRelease }));
jest.mock('pg', () => ({ Pool: jest.fn(() => ({ connect: mockPgConnect, end: mockPgEnd, on: jest.fn() })) }));
const { createAdapter } = require('./adapters');

beforeEach(() => {
  jest.clearAllMocks();
  mockMysqlQuery.mockImplementation(async sql => [sql.includes('GET_LOCK') ? [{ acquired: 1 }] : []]);
  mockPgQuery.mockResolvedValue({ rows: [] });
});

test('MySQL binds values, owns a connection and releases the migration lock', async () => {
  const adapter = await createAdapter({ engine: 'mysql' });
  await adapter.transaction(async query => query('SELECT id FROM rbac_users WHERE login = ?', ["x' OR 1=1"]), {
    write: true,
    migration: true,
  });
  expect(mockMysqlQuery).toHaveBeenCalledWith('SELECT id FROM rbac_users WHERE login = ?', ["x' OR 1=1"]);
  expect(mockMysqlQuery.mock.calls.map(([sql]) => sql)).toEqual([
    "SELECT GET_LOCK(CONCAT(DATABASE(), ':rbac-migrate'), 10) AS acquired",
    'BEGIN',
    'SELECT id FROM rbac_users WHERE login = ?',
    'COMMIT',
    "SELECT RELEASE_LOCK(CONCAT(DATABASE(), ':rbac-migrate'))",
  ]);
  expect(mockMysqlRelease).toHaveBeenCalledTimes(1);
  await adapter.close();
  expect(mockMysqlEnd).toHaveBeenCalledTimes(1);
});

test('MySQL read transactions use repeatable read and errors roll back', async () => {
  const adapter = await createAdapter({ engine: 'mysql' });
  await expect(
    adapter.transaction(async () => {
      throw new Error('failure');
    })
  ).rejects.toThrow('failure');
  expect(mockMysqlQuery.mock.calls.map(([sql]) => sql)).toEqual([
    'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ',
    'BEGIN',
    'ROLLBACK',
  ]);
  expect(mockMysqlRelease).toHaveBeenCalledTimes(1);
});

test('MySQL migration lock timeout prevents migration execution', async () => {
  mockMysqlQuery.mockResolvedValue([[{ acquired: 0 }]]);
  const adapter = await createAdapter({ engine: 'mysql' });
  const migration = jest.fn();
  await expect(adapter.transaction(migration, { write: true, migration: true })).rejects.toThrow('lock timeout');
  expect(migration).not.toHaveBeenCalled();
  expect(mockMysqlRelease).toHaveBeenCalledTimes(1);
});

test('PG converts placeholder syntax without interpolating parameter values', async () => {
  const adapter = await createAdapter({ engine: 'postgres' });
  await adapter.transaction(query =>
    query('SELECT id FROM rbac_users WHERE provider = ? AND login = ?', ['oauth', '?'])
  );
  expect(mockPgQuery).toHaveBeenCalledWith('BEGIN ISOLATION LEVEL REPEATABLE READ', []);
  expect(mockPgQuery).toHaveBeenCalledWith('SELECT id FROM rbac_users WHERE provider = $1 AND login = $2', [
    'oauth',
    '?',
  ]);
  expect(mockPgRelease).toHaveBeenCalledTimes(1);
});

test('PG migration failures roll back and release the connection', async () => {
  const adapter = await createAdapter({ engine: 'postgres' });
  await expect(
    adapter.transaction(
      async () => {
        throw new Error('migration failed');
      },
      { write: true, migration: true }
    )
  ).rejects.toThrow('migration failed');
  expect(mockPgQuery).toHaveBeenCalledWith('SELECT pg_advisory_xact_lock(73104291)', []);
  expect(mockPgQuery).toHaveBeenCalledWith('ROLLBACK', []);
  expect(mockPgRelease).toHaveBeenCalledTimes(1);
});
