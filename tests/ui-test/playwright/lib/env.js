const path = require('path');

try {
  process.loadEnvFile(path.join(__dirname, '..', '.env'));
} catch (e) {
  // No .env file: the variables must come from the environment.
}

const MISP_URL = (process.env.MISP_URL || 'https://localhost:8443').replace(/\/$/, '');
const AUTH_DIR = path.join(__dirname, '..', '.auth');

// The roles used in the Markdown tests, keyed by the name used in the specs.
const ROLES = {
  siteAdmin: { prefix: 'SITE_ADMIN', org: 'ADMIN' },
  userA: { prefix: 'USER_A', org: 'ADMIN' },
  orgAdminA: { prefix: 'ORG_ADMIN_A', org: 'ADMIN' },
  userB: { prefix: 'USER_B', org: 'QA-Org-B' },
  orgAdminB: { prefix: 'ORG_ADMIN_B', org: 'QA-Org-B' },
};

function credentials(role) {
  const { prefix } = ROLES[role];
  const email = process.env[`${prefix}_EMAIL`];
  const password = process.env[`${prefix}_PASSWORD`];
  const key = process.env[`${prefix}_KEY`];
  if (!email || !password || !key) {
    throw new Error(`Set ${prefix}_EMAIL, ${prefix}_PASSWORD and ${prefix}_KEY in .env`);
  }
  return { email, password, key };
}

const storageState = (role) => path.join(AUTH_DIR, `${role}.json`);

module.exports = { MISP_URL, AUTH_DIR, ROLES, credentials, storageState };
