// Dedicated rbac_ tables: do not alter Team storage or generated storageModel.js.
const SCHEMA_VERSION = 1;
const BUILTIN_ROLES = ['anonymous-user', 'logged-user', 'superadmin'];

async function migrate(adapter) {
  await adapter.transaction(
    async query => {
      const suffix = adapter.engine === 'mysql' ? ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin' : '';
      const textType = adapter.engine === 'mysql' ? 'LONGTEXT' : 'TEXT';
      const create = (name, fields) => query(`CREATE TABLE IF NOT EXISTS rbac_${name} (${fields})${suffix}`);
      await create('schema_version', 'id INTEGER PRIMARY KEY, version INTEGER NOT NULL');
      const [version] = await query('SELECT version FROM rbac_schema_version WHERE id = 1');
      if (version && Number(version.version) !== SCHEMA_VERSION) {
        throw new Error('DBGM-00000 Unsupported RBAC schema version');
      }
      if (version) return;
      // UUID keys avoid backend-specific identity/sequence semantics.
      await create(
        'users',
        `id VARCHAR(36) PRIMARY KEY, provider VARCHAR(32) NOT NULL,
      login VARCHAR(250) NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
      UNIQUE (provider, login), CHECK (enabled IN (0, 1))`
      );
      await create('roles', 'id VARCHAR(36) PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE');
      await create(
        'user_roles',
        `user_id VARCHAR(36) NOT NULL, role_id VARCHAR(36) NOT NULL,
      PRIMARY KEY (user_id, role_id),
      FOREIGN KEY (user_id) REFERENCES rbac_users(id) ON DELETE CASCADE,
      FOREIGN KEY (role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE`
      );
      for (const owner of ['user', 'role']) {
        const target = owner === 'user' ? 'users' : 'roles';
        await create(
          `${owner}_permissions`,
          `id VARCHAR(36) PRIMARY KEY, ${owner}_id VARCHAR(36) NOT NULL,
        permission VARCHAR(500) NOT NULL,
        FOREIGN KEY (${owner}_id) REFERENCES rbac_${target}(id) ON DELETE CASCADE`
        );
        // Scope is normalized JSON, validated before persistence. Common across all backends.
        for (const kind of ['connections', 'databases', 'tables', 'files']) {
          await create(
            `${owner}_${kind}`,
            `id VARCHAR(36) PRIMARY KEY, ${owner}_id VARCHAR(36) NOT NULL,
          rule ${textType} NOT NULL,
          FOREIGN KEY (${owner}_id) REFERENCES rbac_${target}(id) ON DELETE CASCADE`
          );
        }
      }
      await create('revision', 'id INTEGER PRIMARY KEY, version INTEGER NOT NULL');
      await create(
        'audit',
        `id VARCHAR(36) PRIMARY KEY, actor VARCHAR(300) NOT NULL,
      action VARCHAR(100) NOT NULL, detail ${textType} NOT NULL, created_at VARCHAR(32) NOT NULL`
      );
      // MySQL DDL commits implicitly. Inspect indexes to make a partial first migration resumable.
      for (const [table, column] of [
        ['user_roles', 'role_id'],
        ...['user', 'role'].flatMap(owner =>
          ['permissions', 'connections', 'databases', 'tables', 'files'].map(kind => [
            `${owner}_${kind}`,
            `${owner}_id`,
          ])
        ),
      ]) {
        const name = `rbac_${table}_${column}_idx`;
        if (adapter.engine === 'mysql') {
          const rows = await query(
            `SELECT index_name FROM information_schema.statistics
          WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`,
            [`rbac_${table}`, name]
          );
          if (rows.length) continue;
        }
        await query(
          `CREATE INDEX ${adapter.engine === 'mysql' ? '' : 'IF NOT EXISTS '}${name} ON rbac_${table} (${column})`
        );
      }
      // Seed data and version in a separate transaction; MySQL DDL above has committed.
    },
    { write: true, migration: true }
  );
  await adapter.transaction(
    async query => {
      if (adapter.engine === 'postgres') await query('SELECT pg_advisory_xact_lock(73104291)');
      const [version] = await query('SELECT version FROM rbac_schema_version WHERE id = 1');
      if (version) return;
      for (const role of BUILTIN_ROLES) await query('INSERT INTO rbac_roles (id, name) VALUES (?, ?)', [role, role]);
      await query('INSERT INTO rbac_revision (id, version) VALUES (1, 0)');
      await query('INSERT INTO rbac_schema_version (id, version) VALUES (1, ?)', [SCHEMA_VERSION]);
    },
    { write: true, migration: true }
  );
}

module.exports = { migrate, BUILTIN_ROLES };
