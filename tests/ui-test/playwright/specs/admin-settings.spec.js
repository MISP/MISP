// ../../admin/settings/settings.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

// Row of a setting in its tab of /servers/serverSettings, found with the search box.
async function findSetting(page, name) {
  await page.goto('/servers/serverSettings');
  const panel = page.getByRole('tabpanel').filter({ visible: true });
  await panel.getByRole('textbox', { name: /Search a setting/ }).fill(name);
  const found = panel.getByRole('row')
    .filter({ has: page.getByRole('cell', { name, exact: true }) });
  await expect(found).toBeVisible();
  return found;
}

async function editSetting(page, name, value) {
  const settingRow = await findSetting(page, name);
  await settingRow.getByRole('button').first().click();
  const form = settingRow.locator('form.ss-edit-form');
  await form.locator('.ss-input').fill(value);
  await form.locator('[data-ss-accept]').click();
  await expect(form).toBeHidden();
  return settingRow;
}

test('Setting – invalid value for a list setting', async ({ page, api, cleanup }) => {
  const name = 'MISP.default_event_distribution';
  cleanup(await api.keepSetting(name));

  // The settings page only offers the five distribution levels...
  const settingRow = await findSetting(page, name);
  await settingRow.getByRole('button').first().click();
  const options = settingRow.locator('form.ss-edit-form select option');
  await expect(options).toHaveCount(5);
  expect(await options.evaluateAll((os) => os.map((o) => o.value))).toEqual(['0', '1', '2', '3', '4']);
  await expectScreen(settingRow, 'admin-setting-invalid-option.png');

  // ...and the server must refuse any other value.
  const res = await api.setSetting(name, '9');
  blockedBy('New bug: MISP.default_event_distribution accepts 9 through serverSettingsEdit '
    + '("Field updated"), although only 0 to 4 are valid');
  expect(await api.getSetting(name)).not.toBe('9');
  expect(res.status).toBeGreaterThanOrEqual(400);
});

test('Setting – text with emoji', async ({ page, browser, api, ts, cleanup }) => {
  const name = 'MISP.welcome_text_top';
  const text = `QA welcome 🚀 ${ts}`;
  cleanup(await api.keepSetting(name));

  await editSetting(page, name, text);
  await expectNoErrorPage(page);
  expect(await api.getSetting(name)).toBe(text);

  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  cleanup(() => context.close());
  const login = await context.newPage();
  await login.goto('/users/login');
  await expect(login.getByText(text)).toBeVisible();
  await expectScreen(login.getByText(text), 'admin-setting-emoji.png');

  await editSetting(page, name, '');
  await expectNoErrorPage(page);
  await expect.poll(() => api.getSetting(name)).toBe('');
});

test('Diagnostics page', async ({ page }) => {
  await page.goto('/servers/serverSettings');
  const start = Date.now();
  await page.goto('/servers/serverSettings/diagnostics');
  expect(Date.now() - start).toBeLessThan(5_000);
  const panel = page.locator('#tab-diagnostics');
  await expect(panel.getByText('Version information')).toBeVisible();
  await expect(panel.getByText('Database status')).toBeVisible();
  await expectNoErrorPage(page);
  await page.getByRole('tab', { name: 'Workers' }).click();
  await expect(page.locator('#tab-workers')).toContainText(/default/i);
  await expectScreen(page.getByRole('tablist'), 'admin-diagnostics.png');
});

test('Admin pages load', async ({ page }) => {
  await page.goto('/servers/serverSettings');
  for (const path of ['/jobs/index', '/feeds/index', '/workflows/index', '/admin/logs/index',
    '/servers/index']) {
    await test.step(path, async () => {
      const start = Date.now();
      const res = await page.goto(path);
      expect(res.status()).toBeLessThan(400);
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      expect(Date.now() - start, `${path} took too long`).toBeLessThan(2_000);
      await expectNoErrorPage(page);
    });
  }
  await expectScreen(page.getByRole('heading', { level: 1 }), 'admin-pages.png');
});
