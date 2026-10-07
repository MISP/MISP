// ../../account/keys/auth-keys.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, dialog, row,
  throwawayUser, loginThrowaway,
} = require('../helpers');
const { MispApi } = require('../harness/api');

// Adding or deleting a key renews the user's session, which would end the
// stored QA sessions: keys are added by a throwaway "User" of ADMIN.
test.describe('as user of ADMIN', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test.beforeEach(async ({ page, api, cleanup }) => {
    await loginThrowaway(page, await throwawayUser(api, cleanup, 'qa-keys'));
  });

// My Profile -> Auth keys -> Add authentication key; returns the dialog.
async function submitKey(page, { comment, allowedIps, expiration, readOnly = false }) {
  await page.goto('/users/view/me');
  await page.getByRole('tab', { name: /^Auth keys/ }).click();
  await page.getByRole('button', { name: 'Add authentication key' })
    .or(page.getByRole('link', { name: 'Add authentication key' })).click();
  const form = dialog(page);
  await expect(form.getByRole('heading', { name: 'Add Auth Key' })).toBeVisible();
  await form.locator('#AuthKeyComment').fill(comment);
  if (allowedIps) await form.locator('#AuthKeyAllowedIps').fill(allowedIps);
  if (expiration) await form.locator('#AuthKeyExpiration').fill(expiration);
  if (readOnly) await form.locator('#AuthKeyReadOnly').check();
  await form.getByRole('button', { name: 'Add Auth Key' }).click();
  return form;
}

// Reads the new key, shown once; hides it before any screenshot.
async function createdKey(page) {
  const form = dialog(page);
  await expect(form.getByRole('heading', { name: 'Auth key created' })).toBeVisible();
  const box = form.getByRole('textbox');
  const key = await box.inputValue();
  expect(key).toMatch(/^[A-Za-z0-9]{40}$/);
  await box.evaluate((e) => { e.value = 'QA-KEY-HIDDEN'; });
  return key;
}

async function keysWithComment(api, comment) {
  const keys = await api.get('/auth_keys/index');
  return keys.map((k) => k.AuthKey || k).filter((k) => k.comment === comment);
}

  test('Auth key – read only', async ({ page, api, ts, cleanup }) => {
    const comment = `QA read-only ${ts}`;
    const info = `QA read-only key event ${ts}`;
    cleanup(() => api.deleteEventsByInfo(info));

    await submitKey(page, { comment, readOnly: true });
    const key = await createdKey(page);
    await expectScreen(dialog(page), 'account-key-read-only.png');

    const client = new MispApi(key);
    cleanup(() => client.dispose());
    expect((await client.raw('GET', '/events/index')).status).toBe(200);
    const add = await client.raw('POST', '/events/add', { Event: { info, distribution: 0 } });
    expect(add.status).toBe(403);
    expect(add.text).toContain('You do not have permission to use this functionality.');
  });

  test('Auth key – allowed IPs', async ({ page, api, ts, cleanup }) => {
    const comment = `QA ip allowlist ${ts}`;

    await submitKey(page, { comment, allowedIps: '10.9.9.9' });
    const key = await createdKey(page);
    await expectScreen(dialog(page), 'account-key-allowed-ips.png');

    const client = new MispApi(key);
    cleanup(() => client.dispose());
    const res = await client.raw('GET', '/events/index');
    expect(res.status).toBe(403);
    expect(res.text).toContain('It is not possible to use this Auth key from your IP address');
  });

  test('Auth key – invalid allowed IP', async ({ page, api, ts }) => {
    const comment = `QA invalid ip ${ts}`;

    const form = await submitKey(page, { comment, allowedIps: '999.0.0.0/99' });
    await page.waitForLoadState('networkidle');
    await expectNoErrorPage(page);
    await expect(form.getByRole('heading', { name: 'Add Auth Key' })).toBeVisible();
    await expect(form.getByRole('heading', { name: 'Auth key created' })).toHaveCount(0);
    expect(await keysWithComment(api, comment)).toHaveLength(0);
    blockedBy('Recommendation 3 (an invalid IP range is refused without saying why)');
    await expect(form.getByText(/is not valid IP range/)).toBeVisible();
    await expectScreen(form, 'account-key-invalid-ip.png');
  });

  test('Auth key – expiration in the past', async ({ page, api, ts, cleanup }) => {
    const comment = `QA expired ${ts}`;

    await submitKey(page, { comment, expiration: '2020-01-01' });
    await expectNoErrorPage(page);
    // Accepted without a warning: the key must then be marked expired and refused.
    const key = await createdKey(page);
    const client = new MispApi(key);
    cleanup(() => client.dispose());
    const res = await client.raw('GET', '/events/index');
    expect(res.status).toBe(403);
    expect(res.text).toMatch(/Authentication failed/);

    const [stored] = await keysWithComment(api, comment);
    await page.goto('/auth_keys/index');
    const keyRow = row(page.getByRole('main'), `#${stored.id}`);
    await expect(keyRow.getByRole('cell', { name: 'Expired', exact: true })).toBeVisible();
    await expectScreen(keyRow, 'account-key-expired.png');
  });
});

test.describe('as user of QA-Org-B', () => {
  test.use({ role: 'userB' });

  test('Auth keys – only my keys', async ({ page, api }) => {
    const all = (await api.get('/auth_keys/index')).map((k) => k.AuthKey || k);
    const users = (await api.get('/admin/users/index')).map((u) => u.User || u);
    const userB = users.find((u) => u.email === 'qa-user-b@qa-org-b.test');
    const others = all.filter((k) => String(k.user_id) !== String(userB.id));
    expect(others.length).toBeGreaterThan(0);

    await page.goto('/auth_keys/index');
    const main = page.getByRole('main');
    const ids = (await main.locator('tbody').getByRole('link', { name: /^#\d+$/ }).allInnerTexts())
      .map((t) => t.trim().slice(1));
    expect(ids.length).toBeGreaterThan(0);
    for (const id of ids) {
      expect(String(all.find((k) => String(k.id) === id)?.user_id)).toBe(String(userB.id));
    }
    for (const key of others) expect(ids).not.toContain(String(key.id));
    await expectNoErrorPage(page);
    await expectScreen(main.locator('thead'), 'account-key-own-only.png');
  });
});
