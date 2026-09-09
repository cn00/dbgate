const KINDS = ['permissions', 'connections', 'databases', 'tables', 'files'];
const fields = {
  connections: ['connection_conid', 'effect'],
  databases: ['connection_conid', 'database_names_list', 'database_names_regex', 'database_permission_role_id'],
  tables: [
    'connection_conid',
    'database_names_list',
    'database_names_regex',
    'schema_names_list',
    'schema_names_regex',
    'table_names_list',
    'table_names_regex',
    'table_permission_role_id',
    'table_permission_scope_id',
  ],
  files: ['folder_name', 'file_names_list', 'file_names_regex', 'file_permission_role_id'],
};

function fail(message) {
  throw new Error(`DBGM-00000 ${message}`);
}

function normalizeLogin(login) {
  if (typeof login !== 'string' || !login.trim() || login.trim().length > 250) fail('Invalid RBAC login');
  return login.trim().toLowerCase();
}

function validateProvider(provider) {
  if (!['oauth', 'ad', 'logins'].includes(provider)) fail('Invalid RBAC identity provider');
  return provider;
}

function normalizeRules(kind, rules) {
  if (!KINDS.includes(kind) || !Array.isArray(rules) || rules.length > 1000) fail('Invalid RBAC permission rules');
  if (kind === 'permissions') {
    return [
      ...new Set(
        rules.map(rule => {
          if (typeof rule !== 'string' || rule.length > 500 || !/^~?[a-zA-Z0-9_/*:.-]+$/.test(rule)) {
            fail('Invalid RBAC permission');
          }
          return rule;
        })
      ),
    ];
  }
  return rules.map(rule => {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) fail('Invalid RBAC resource rule');
    const result = {};
    for (const [key, value] of Object.entries(rule)) {
      if (!fields[kind].includes(key)) fail(`Unknown RBAC rule field: ${key}`);
      if (key.endsWith('_id')) {
        const allowed = key === 'table_permission_scope_id' ? 9 : key === 'file_permission_role_id' ? 2 : 5;
        if (!Number.isInteger(value) || value > -1 || value < -allowed) fail(`Invalid RBAC rule field: ${key}`);
      } else if (typeof value !== 'string' || value.length > 1000) {
        fail(`Invalid RBAC rule field: ${key}`);
      }
      // Regex rules from trusted administrators only. Limit size and reject invalid syntax.
      if (key.endsWith('_regex') && value) {
        if (value.length > 250) fail('RBAC regular expression is too long');
        try {
          new RegExp(value, 'i');
        } catch (_) {
          fail('Invalid RBAC regular expression');
        }
      }
      result[key] = value;
    }
    if (result.connection_conid && !/^[a-zA-Z0-9_:.-]+$/.test(result.connection_conid)) {
      fail('RBAC connection rules require an exact connection identifier');
    }
    const roleField = {
      databases: 'database_permission_role_id',
      tables: 'table_permission_role_id',
      files: 'file_permission_role_id',
    }[kind];
    if (roleField && result[roleField] == null) fail(`Missing ${roleField}`);
    if (kind === 'connections' && (!result.connection_conid || !['allow', 'deny'].includes(result.effect))) {
      fail('Connection rule requires connection_conid and allow/deny effect');
    }
    if (kind === 'tables' && result.table_permission_scope_id == null) fail('Missing table_permission_scope_id');
    return result;
  });
}

// Existing permission compiler is last-match-wins. Sort broad first and deny last.
function permissionSpecificity(rule) {
  const value = rule.replace(/^~/, '');
  return [value.replace(/\*/g, '').length, value.includes('*') ? 0 : 1];
}

function compareScores(a, b) {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function mergePermissions(rules) {
  return [
    '~*',
    ...[...new Set(rules)].sort(
      (a, b) =>
        compareScores(permissionSpecificity(a), permissionSpecificity(b)) ||
        Number(a.startsWith('~')) - Number(b.startsWith('~')) ||
        a.localeCompare(b)
    ),
  ];
}

function resourceSpecificity(rule) {
  // Scope hierarchy: connection > database > schema > object; exact/list > regex > unrestricted.
  return [
    rule.connection_conid ? 1 : 0,
    rule.database_names_list ? 2 : rule.database_names_regex ? 1 : 0,
    rule.schema_names_list ? 2 : rule.schema_names_regex ? 1 : 0,
    rule.folder_name ? 1 : 0,
    rule.table_names_list || rule.file_names_list ? 2 : rule.table_names_regex || rule.file_names_regex ? 1 : 0,
    rule.table_permission_scope_id && rule.table_permission_scope_id !== -1 ? 1 : 0,
  ];
}

function privilege(rule) {
  if (rule.effect) return rule.effect === 'deny' ? 0 : 1;
  if (rule.file_permission_role_id) return rule.file_permission_role_id === -2 ? 0 : 1;
  const value = rule.table_permission_role_id ?? rule.database_permission_role_id;
  return value === -5 ? 0 : -value;
}

function mergeResourceRules(rules) {
  return [...rules].sort(
    (a, b) => compareScores(resourceSpecificity(a), resourceSpecificity(b)) || privilege(b) - privilege(a)
  );
}

module.exports = {
  KINDS,
  fail,
  normalizeLogin,
  validateProvider,
  normalizeRules,
  mergePermissions,
  mergeResourceRules,
};
