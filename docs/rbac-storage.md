# RBAC storage

This implementation provides the storage layer, authentication-provider integration and a
superadmin management API. PostgreSQL/MySQL use a shared database; SQLite uses a local file.
The default remains `env`, preserving existing environment permission behavior.

## Delivery boundary

Implemented: migrations, bootstrap identity, users/roles, direct and inherited permissions,
connection/database/table/file rule storage, request snapshots, transactional audit/versioning,
OAuth/AD/environment-login integration, management API, and environment import.

The Svelte management UI, IdP group synchronization, and a complete audit of all data/file/SQL
execution endpoints are separate work. Existing connection checks, database/script checks and
schema filtering now use the dynamic provider, but storing a table/file restriction does **not**
prove that every existing API enforces it. For example, file controller operations still primarily
check folder permissions. Do not treat this delivery as a completed fine-grained security boundary
or enable it for untrusted users until endpoint enforcement and end-to-end tests are completed.
MCP is explicitly rejected in dynamic mode until it has a separate identity/role mapping.

## Configuration

| Variable | Meaning |
| --- | --- |
| `RBAC_STORAGE_ENGINE` | `env` (default), `postgres`, `mysql`, or `sqlite` |
| `RBAC_STORAGE_SERVER` | Required for PG/MySQL |
| `RBAC_STORAGE_PORT` | Defaults to 5432 / 3306 |
| `RBAC_STORAGE_DATABASE` | Existing dedicated database for PG/MySQL; not auto-created |
| `RBAC_STORAGE_USER`, `RBAC_STORAGE_PASSWORD` | Required for PG/MySQL |
| `RBAC_STORAGE_SSL` | `true`/`1` enables TLS with certificate verification; default off |
| `RBAC_STORAGE_FILE` | SQLite absolute file path; parent directory must already exist |
| `RBAC_BOOTSTRAP_PROVIDER` | `oauth`, `ad`, or `logins`; must match the configured authentication provider |
| `RBAC_BOOTSTRAP_LOGIN` | Existing external identity to make superadmin on an empty RBAC store |
| `RBAC_TOKEN_SECRET` | At least 32 characters; required and identical across PG/MySQL API replicas |

Bootstrap creates a local authorization identity, not an OAuth/AD account or password. Bootstrap
variables may be removed after successful initialization. They never overwrite existing users or
restore privileges on restart. Initialization requires at least one enabled superadmin.
Database migration/connection/configuration errors prevent the HTTP listener from starting;
there is no backend fallback. `STORAGE_DATABASE` and `SKIP_ALL_AUTH` cannot be combined with
dynamic RBAC. The legacy Team storage controller is independent and remains unchanged.

Configure OAuth/AD/`LOGIN_PASSWORD_*` authentication separately as before. Dynamic OAuth mode
requires `OAUTH_LOGIN_FIELD` and refuses tokens without that nonempty claim. Identity keys are
`(provider, login.trim().toLowerCase())`; use a stable unique claim from a trusted IdP. An IdP or
issuer change requires reviewing identity mappings; groups currently only affect existing login
allowlists. Credentials and upstream OAuth tokens are not stored in RBAC tables.

The existing OAuth token-validation implementation is preserved. This storage change does not
add OIDC discovery/JWKS validation or redesign the OAuth protocol flow.

SQLite development example, with the login password supplied through the existing authentication
configuration rather than placed in the RBAC database:

```env
AUTH_PROVIDER=logins
RBAC_STORAGE_ENGINE=sqlite
RBAC_STORAGE_FILE=/data/dbgate-rbac.sqlite
RBAC_BOOTSTRAP_PROVIDER=logins
RBAC_BOOTSTRAP_LOGIN=admin
```

For PostgreSQL/MySQL, replace the engine/file settings with the server/database/user/password
variables and supply a randomly generated shared `RBAC_TOKEN_SECRET`. Keep that secret in the
deployment secret store. SQLite may also set it; otherwise tokens expire on process restart.
Enabling dynamic mode requires signing in again: its JWT carries `amoid`, login and `rbacUserId`,
plus standard timestamps. No roles or permissions are embedded. Deleting/recreating a login
cannot reactivate its old token. The legacy admin-password login is disabled in dynamic mode;
superadmins sign in through the normal configured provider.

## Schema and transactions

`packages/api/src/rbac/migrations.js` owns versioned `rbac_` tables. It neither reads nor edits
generated `storageModel.js`. The names and fields follow the existing permission model where
practical; this is not a replacement Team storage implementation.

- `rbac_users`, `rbac_roles`, `rbac_user_roles`: identities and memberships.
- `rbac_{user,role}_permissions`: string permission entries.
- `rbac_{user,role}_{connections,databases,tables,files}`: validated resource rules serialized
  as JSON text, with an indexed owner foreign key. Connection IDs reference the existing connection
  identifiers; business database credentials and connection definitions remain where they are.
- `rbac_schema_version`: migration version; unsupported versions fail initialization.
- `rbac_revision`: global permission version.
- `rbac_audit`: actor, operation, structured change detail and UTC time, committed with each change.

UUID primary keys avoid auto-increment/sequence differences. MySQL tables explicitly use InnoDB
and `utf8mb4_bin`, matching case-sensitive IDs on PG/SQLite after explicit login normalization.
Schema creation is idempotent and protected by PG advisory locks, MySQL named locks, or SQLite
write transactions. MySQL DDL commits implicitly; version 1 can resume partial table/index creation.
Version/data seeds are committed together after DDL. Future schema changes need new migrations.

Policy edits serialize on the revision row (SQLite: `BEGIN IMMEDIATE`), validate the actor and
last-admin invariant inside the same transaction, append audit data and increment the global
revision. This handles changes to shared roles without updating every member row.
Foreign keys and cascading deletes keep memberships and rules consistent.

Each HTTP request loads one repeatable-read permission snapshot. It is reused only within that
request, with no cross-request user cache. The next request sees committed changes, including
disabled users. In-flight queries/streams are not cancelled when privileges are revoked.

## Permission semantics

SQL-backed users start with `~*` (deny all); the implicit `logged-user` role starts empty.
`superadmin` membership yields `*` and exclusively authorizes management operations; merely
granting `admin/*` or `*` to another role does not grant management API access. Builtin role IDs
cannot be renamed/deleted. `anonymous-user` is reserved and does not grant anonymous access.

General permission strings use existing syntax (`widgets/database`, `dbops/query`, `connections/id`,
`~widgets/admin`). Rules are sorted by non-wildcard length, then exact over wildcard, then deny
over allow. The existing frontend/backend last-match compiler consumes this deterministic list.
At identical scopes, restrictive rules win, regardless of direct-user versus role origin.

Resource rule specificity compares connection, database, schema, folder, object-name and object-type
scope in that order; a list is more specific than regex, which is more specific than unrestricted.
At equal specificity the least permissive role wins. Specificity does not attempt mathematical
containment of two arbitrary regexes or overlapping lists. Regexes are administrator-authored,
syntax-validated and length-limited; avoid expensive expressions.

Rule fields follow `hasPermission.js`:

| Kind | Example |
| --- | --- |
| `permissions` | `"widgets/database"` |
| `connections` | `{"connection_conid":"warehouse","effect":"allow"}` |
| `databases` | `{"connection_conid":"warehouse","database_names_list":"sales","database_permission_role_id":-2}` |
| `tables` | `{"connection_conid":"warehouse","table_names_list":"invoices","table_permission_role_id":-1,"table_permission_scope_id":-2}` |
| `files` | `{"folder_name":"sql","file_names_list":"report.sql","file_permission_role_id":-1}` |

Database roles: -1 view, -2 read content, -3 write data, -4 run script, -5 deny.
Table roles: -1 read, -2 update, -3 create/update/delete, -4 run script, -5 deny.
File roles: -1 allow, -2 deny. Table scopes use the existing -1 through -9 mapping.
List fields are newline separated. Resource grants do not automatically grant widgets or actions.
Existing `all-databases` / `all-tables` checks bypass their corresponding resource restrictions;
grant those permissions only when unrestricted access is intended.

## Management API

All routes are authenticated POST requests under `WEB_ROOT` if configured. The actor comes from
the verified request identity, never from request JSON. Every mutation rechecks superadmin status
inside its transaction. Errors follow the existing controller `apiErrorMessage` response convention.

| Route | JSON request |
| --- | --- |
| `/rbac/inspect` | `{}`; returns users, memberships, rules and the latest 100 audit records |
| `/rbac/save-role` | `{"name":"analyst"}`; optional `id` updates a custom role |
| `/rbac/save-user` | `{"provider":"oauth","login":"alice","enabled":true,"roleIds":["role-id"]}` |
| `/rbac/replace-rules` | `{"owner":"role","id":"role-id","kind":"permissions","rules":["widgets/database"]}` |
| `/rbac/delete-principal` | `{"owner":"user","id":"user-id"}` |

Save-user accepts optional `id`; it replaces the full identity/status/membership configuration,
so send all memberships on update. Omitted `enabled` means true; omitted `roleIds` means no explicit
roles. Replace-rules replaces all entries of one kind for the principal. Management UI is not included.

## Import and deployment

Run from the repository root with configuration already exported in the process environment:

```sh
node packages/api/src/rbac/cli.js initialize
node packages/api/src/rbac/cli.js inspect oauth admin@example.com
node packages/api/src/rbac/cli.js plan-import oauth
node packages/api/src/rbac/cli.js import-env oauth admin@example.com --accept-permission-changes
```

`plan-import` does not connect to a database or print passwords. It discovers `LOGIN`,
`LOGIN_PASSWORD_*` and `LOGIN_PERMISSIONS_*`. Missing permissions become explicit `*`, matching
legacy unrestricted access. Dynamic sorting/default-deny differs from legacy rule ordering:
review the dry-run and test effective access before import. Imports are transactional and refuse
to overwrite existing identities; omit bootstrap/existing users from the import environment.

Install the declared API dependencies using the existing workspace workflow. `pg` and `mysql2`
are direct dependencies. `better-sqlite3` is optional to permit PG/MySQL-only builds; SQLite startup
fails if the native module is unavailable. Existing webpack volatile-dependency packaging includes
these drivers. No driver version changes are introduced by this feature.

Use local persistent storage for SQLite with exactly one API instance. Keep the file out of served
files/upload directories, protect it with OS file permissions, and do not share it over SMB/NFS.
SQLite uses WAL, foreign keys and a 5-second busy timeout. Use a consistent SQLite backup mechanism
or stop the process before copying the database; a live copy of only the main file can miss WAL data.
PG/MySQL support multiple API instances with identical JWT secrets and authentication settings.
Database backup, restore and migration credentials remain deployment responsibilities.

## Validation

```sh
node node_modules/jest/bin/jest.js --config packages/api/package.json --runInBand packages/api/src/rbac
```

Repository tests default to a temporary real SQLite database, removed after tests. To run the same
suite against PG/MySQL, point `RBAC_STORAGE_*` and `RBAC_TOKEN_SECRET` at a **dedicated empty test
database** and set `RBAC_TEST_ENGINE=postgres` or `mysql`. Tests create test users/roles and retain
SQL database contents; recreate the disposable database before each run.

Storage tests do not replace OAuth provider end-to-end tests, API authorization auditing, or the
future Cypress management-UI suite. Release readiness needs all three database integration suites
and the remaining endpoint enforcement work.
