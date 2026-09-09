// Each transaction owns one connection. No SQL identifiers originate from API input.
async function createAdapter(config) {
  if (config.engine === 'sqlite') {
    const Database = require('better-sqlite3');
    const db = new Database(config.filename, { timeout: 5000 });
    try {
      db.pragma('foreign_keys = ON');
      db.pragma('journal_mode = WAL');
      db.pragma('busy_timeout = 5000');
    } catch (err) {
      db.close();
      throw err;
    }
    let queue = Promise.resolve();
    const query = async (sql, params = []) => {
      const stmt = db.prepare(sql);
      return stmt.reader ? stmt.all(...params) : (stmt.run(...params), []);
    };
    return {
      engine: 'sqlite',
      transaction(fn, { write = false } = {}) {
        const result = queue.then(async () => {
          db.exec(write ? 'BEGIN IMMEDIATE' : 'BEGIN');
          try {
            const value = await fn(query);
            db.exec('COMMIT');
            return value;
          } catch (err) {
            db.exec('ROLLBACK');
            throw err;
          }
        });
        queue = result.catch(() => {});
        return result;
      },
      async close() {
        await queue;
        db.close();
      },
    };
  }

  const { host, port, database, user, password, ssl } = config;
  const pool =
    config.engine === 'postgres'
      ? new (require('pg').Pool)({ host, port, database, user, password, ssl, max: 5, connectionTimeoutMillis: 5000 })
      : require('mysql2')
          .createPool({
            host,
            port,
            database,
            user,
            password,
            ssl,
            connectionLimit: 5,
            connectTimeout: 5000,
            charset: 'utf8mb4',
          })
          .promise();
  // An idle PG connection can emit an error independently of a request.
  if (config.engine === 'postgres') pool.on('error', () => {});
  return {
    engine: config.engine,
    async transaction(fn, { write = false, migration = false } = {}) {
      const client = config.engine === 'postgres' ? await pool.connect() : await pool.getConnection();
      let mysqlLock = false;
      const query = async (sql, params = []) => {
        if (config.engine === 'postgres') {
          let index = 0;
          return (
            await client.query(
              sql.replace(/\?/g, () => `$${++index}`),
              params
            )
          ).rows;
        }
        const [rows] = await client.query(sql, params);
        return Array.isArray(rows) ? rows : [];
      };
      try {
        if (migration && config.engine === 'mysql') {
          const [row] = await query("SELECT GET_LOCK(CONCAT(DATABASE(), ':rbac-migrate'), 10) AS acquired");
          if (Number(row.acquired) !== 1) throw new Error('DBGM-00000 RBAC migration lock timeout');
          mysqlLock = true;
        }
        if (!write && config.engine === 'mysql') await query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
        await query(!write && config.engine === 'postgres' ? 'BEGIN ISOLATION LEVEL REPEATABLE READ' : 'BEGIN');
        if (migration && config.engine === 'postgres') await query('SELECT pg_advisory_xact_lock(73104291)');
        const result = await fn(query);
        await query('COMMIT');
        return result;
      } catch (err) {
        await query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        if (mysqlLock) await query("SELECT RELEASE_LOCK(CONCAT(DATABASE(), ':rbac-migrate'))").catch(() => {});
        client.release();
      }
    },
    close: () => pool.end(),
  };
}

module.exports = { createAdapter };
