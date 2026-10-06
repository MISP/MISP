// Logs in once per role; every test reuses the saved session.
const fs = require('fs');
const { test: setup, expect } = require('@playwright/test');
const { ROLES, AUTH_DIR, credentials, storageState } = require('../lib/env');

fs.mkdirSync(AUTH_DIR, { recursive: true });

for (const role of Object.keys(ROLES)) {
  setup(`log in as ${role}`, async ({ page }) => {
    const { email, password } = credentials(role);
    await page.goto('/users/login');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Login' }).click();
    await expect(page).not.toHaveURL(/\/users\/login/);
    await page.context().storageState({ path: storageState(role) });
  });
}
