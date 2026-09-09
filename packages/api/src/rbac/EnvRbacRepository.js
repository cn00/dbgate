class EnvRbacRepository {
  constructor(env = process.env) {
    this.env = env;
  }
  async initialize() {}
  async close() {}
  async getUserByExternalLogin(login) {
    return { id: login, login };
  }
  async getEffectivePermissions(login) {
    return this.env[`LOGIN_PERMISSIONS_${login}`] || this.env.PERMISSIONS;
  }
  async getConnectionPermissions() {
    return [];
  }
  async getDatabasePermissions() {
    return [];
  }
  async getTablePermissions() {
    return [];
  }
  async getFilePermissions() {
    return [];
  }
  async getPermissionVersion() {
    return 0;
  }
}

module.exports = EnvRbacRepository;
