// Example: node packages/api/src/rbac/cli.js inspect oauth admin@example.com
const { createRepository } = require('./index');
const { readRbacConfig } = require('./config');
const { planEnvironmentImport } = require('./importEnvironment');

async function main() {
  const [command, provider, login, confirmation] = process.argv.slice(2);
  if (command === 'plan-import') {
    console.log(JSON.stringify(planEnvironmentImport(process.env, provider), null, 2));
    return;
  }
  if (!['inspect', 'import-env', 'initialize'].includes(command)) {
    throw new Error(
      'DBGM-00000 Usage: cli.js initialize | inspect <provider> <login> | plan-import <provider> | import-env <provider> <admin-login> --accept-permission-changes'
    );
  }
  const config = readRbacConfig();
  if (config.engine === 'env') throw new Error('DBGM-00000 Select a SQL RBAC storage engine');
  const repository = await createRepository(config);
  try {
    if (command === 'initialize') return;
    const actor = await repository.getUserByExternalLogin(login, provider);
    if (!actor) throw new Error('DBGM-00000 Administrator is not registered');
    if (command === 'inspect') {
      console.log(JSON.stringify(await repository.inspect(actor.id), null, 2));
      return;
    }
    if (confirmation !== '--accept-permission-changes') {
      throw new Error('DBGM-00000 Review plan-import first: dynamic RBAC uses default-deny and specificity ordering');
    }
    const plan = planEnvironmentImport(process.env, provider);
    await repository.importEnvironment(actor.id, plan);
    console.log(`Imported ${plan.length} RBAC users`);
  } finally {
    await repository.close();
  }
}

if (require.main === module)
  main().catch(err => {
    console.error(
      err.message?.startsWith('DBGM-00000')
        ? err.message
        : 'DBGM-00000 RBAC operation failed; check configuration and database availability'
    );
    process.exitCode = 1;
  });

module.exports = { main };
