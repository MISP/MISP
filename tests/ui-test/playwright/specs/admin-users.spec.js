// ../../admin/users/users.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, dialog, row, pick,
  throwawayUser, submitLogin,
} = require('../helpers');
const { credentials } = require('../harness/env');
const { MispApi } = require('../harness/api');

test.use({ role: 'siteAdmin' });

async function openAddUser(page) {
  await page.goto('/admin/users/index');
  await page.getByRole('main').getByRole('link', { name: 'Add user', exact: true }).click();
  const form = dialog(page);
  await expect(form.getByRole('heading', { name: 'Add user' })).toBeVisible();
  return form;
}

async function addUser(page, email) {
  const form = await openAddUser(page);
  await form.getByRole('textbox', { name: 'Email' }).fill(email);
  await pick(form.getByRole('combobox', { name: 'Organisation' }), 'ADMIN');
  await expect(form.locator('#adminRoleId')).toHaveValue(/\d+/);
  await form.getByRole('button', { name: 'Create user' }).click();
  return form;
}

const usersWithEmail = async (api, email) => (await api.get('/admin/users/index'))
  .map((u) => u.User || u).filter((u) => u.email.toLowerCase() === email.toLowerCase());

// Users list -> row menu -> Edit, as the site admin.
async function editUser(page, email, change) {
  await page.goto('/admin/users/index');
  await row(page.getByRole('main'), email).locator('button').last().click();
  await page.locator('.dropdown-menu.show').getByRole('link', { name: 'Edit', exact: true }).click();
  const form = dialog(page);
  await expect(form.locator('#UserEmail')).toHaveValue(email);
  await change(form);
  await form.locator('#editCurrentPassword').fill(credentials('siteAdmin').password);
  await form.getByRole('button', { name: 'Save changes' }).click();
  await expect(form).toBeHidden();
  await expect(page.getByText('The user has been saved')).toBeVisible();
  await expectNoErrorPage(page);
  await page.goto('/admin/users/index');
}

// Logs in from a new browser; returns its page (closed by the cleanup).
async function loginElsewhere(browser, cleanup, email, password) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  cleanup(() => context.close());
  const other = await context.newPage();
  await submitLogin(other, email, password);
  return other;
}

test('User add – email already used', async ({ page, api }) => {
  const email = credentials('userA').email;
  const form = await addUser(page, email);
  await expectNoErrorPage(page);
  await expect(form).toBeVisible();
  expect(await usersWithEmail(api, email)).toHaveLength(1);
  await expect(form.getByText(/already (used|in use|exists|registered|taken)/i).first()).toBeVisible();
  await expectScreen(form, 'admin-user-duplicate-email.png');
});

test('User add – same email in upper case', async ({ page, api, cleanup }) => {
  const email = credentials('userA').email.toUpperCase();
  cleanup(() => api.deleteUserByEmail(email));
  const form = await addUser(page, email);
  await expectNoErrorPage(page);
  await expect(form).toBeVisible();
  expect(await usersWithEmail(api, email)).toHaveLength(1);
  await expectScreen(form, 'admin-user-email-case.png');
});

test('User add – invalid email', async ({ page, api, cleanup }) => {
  cleanup(() => api.deleteUserByEmail('not-an-email'));
  const form = await addUser(page, 'not-an-email');
  await expectNoErrorPage(page);
  await expect(form).toBeVisible();
  expect(await usersWithEmail(api, 'not-an-email')).toHaveLength(0);
  await expect(form.getByText(/not a valid e-?mail|invalid e-?mail|valid e-?mail address/i).first())
    .toBeVisible();
  await expectScreen(form, 'admin-user-invalid-email.png');
});

test('User disable', async ({ page, browser, api, cleanup }) => {
  // A throwaway "User" of ADMIN: disabling qa-user-a would end its saved session.
  const user = await throwawayUser(api, cleanup, 'qa-disable');
  const { id } = await api.findUser(user.email);
  const client = new MispApi(await api.createAuthKey(id, 'QA disable'));
  cleanup(() => client.dispose());
  expect((await client.raw('GET', '/events/index')).status).toBe(200);

  await editUser(page, user.email, (form) => form.locator('#sw_disabled').check());
  const refused = await loginElsewhere(browser, cleanup, user.email, user.password);
  await expect(refused.getByText('Your user account has been disabled.')).toBeVisible();
  await expect(refused).toHaveURL(/\/users\/login/);
  expect((await client.raw('GET', '/events/index')).status).toBe(403);
  const userRow = row(page.getByRole('main'), user.email);
  await expect(userRow.getByText('Disabled', { exact: true })).toBeVisible();
  await expectScreen(userRow, 'admin-user-disabled.png');

  await editUser(page, user.email, (form) => form.locator('#sw_disabled').uncheck());
  const allowed = await loginElsewhere(browser, cleanup, user.email, user.password);
  await expect(allowed).not.toHaveURL(/\/users\/login/);
  expect((await client.raw('GET', '/events/index')).status).toBe(200);
});

test('User role change – Read Only', async ({ page, browser, api, cleanup }) => {
  const user = await throwawayUser(api, cleanup, 'qa-readonly');
  // Two comboboxes are named "Role": use the tom-select input.
  await editUser(page, user.email,
    (form) => pick(form.locator('#adminRoleId-ts-control'), 'Read Only'));
  await expect(row(page.getByRole('main'), user.email).getByText('Read Only', { exact: true })).toBeVisible();

  const other = await loginElsewhere(browser, cleanup, user.email, user.password);
  await expect(other).not.toHaveURL(/\/users\/login/);
  await other.goto('/events/index');
  await expect(other.getByRole('heading', { name: 'Events', level: 1 })).toBeVisible();
  const add = other.getByRole('link', { name: 'Add Event' });
  if (await add.count()) {
    await add.first().click();
    await expect(other.getByText('You do not have permission to use this functionality.')).toBeVisible();
  }
  await expectNoErrorPage(other);
  await expectScreen(row(page.getByRole('main'), user.email), 'admin-user-read-only.png');
});

test('User add – empty form', async ({ page, api }) => {
  const before = (await api.get('/admin/users/index')).length;
  const form = await openAddUser(page);
  await form.getByRole('button', { name: 'Create user' }).click();
  await expectNoErrorPage(page);
  await expect(form).toBeVisible();
  expect(await api.get('/admin/users/index')).toHaveLength(before);
  blockedBy('Bug 13 (Add User: an empty form gives no message in the window)');
  await expect(form.locator('.invalid-feedback, .error-message, .alert-danger')
    .filter({ visible: true }).first()).toBeVisible();
  await expectScreen(form, 'admin-user-empty-form.png');
});
