// ../../account/login/login.md
const {
  test, expect, expectScreen, throwawayUser, submitLogin, loginThrowaway,
} = require('../helpers');

// No stored session: these tests log in and out through the form, with a
// throwaway "User" of ADMIN, as failed logins lock the account.
test.use({ storageState: { cookies: [], origins: [] } });

const loginForm = (page) => page.locator('form').filter({ has: page.getByLabel('Email') });

async function logOut(page) {
  await page.getByRole('banner').getByRole('link', { name: /qa-login-/i }).click();
  await page.locator('.dropdown-menu.show').getByRole('link', { name: 'Log out' }).click();
  await expect(page).toHaveURL(/\/users\/login/);
}

test('Login – wrong password', async ({ page, api, ts, cleanup }) => {
  const { email } = await throwawayUser(api, cleanup, 'qa-login');
  const message = page.getByText('Invalid username or password, try again');

  await submitLogin(page, email, 'wrong-password');
  await expect(page).toHaveURL(/\/users\/login/);
  await expect(message).toBeVisible();
  const known = await page.locator('body').innerText();

  await submitLogin(page, `nobody-${ts}@qa.test`, 'wrong-password');
  await expect(page).toHaveURL(/\/users\/login/);
  await expect(message).toBeVisible();
  // Same answer whether the account exists or not.
  expect(await page.locator('body').innerText()).toBe(known);
  await expectScreen(loginForm(page), 'account-login-wrong.png');
});

test('Login – brute force protection', async ({ page, api, cleanup }) => {
  const { email, password } = await throwawayUser(api, cleanup, 'qa-login');

  for (let i = 0; i < 5; i += 1) {
    await submitLogin(page, email, `wrong-password-${i}`);
    await expect(page.getByText('Invalid username or password, try again')).toBeVisible();
  }
  await submitLogin(page, email, password);
  const locked = page.getByText('You have reached the maximum number of login attempts. '
    + 'Please wait 300 seconds and try again.');
  await expect(locked).toBeVisible();
  await expectScreen(locked, 'account-login-bruteforce.png');
});

test('Login – brute force lock expires after 5 minutes', async ({ page, api, cleanup }) => {
  test.skip(!process.env.QA_SLOW, 'Waits 5 minutes: run with QA_SLOW=1');
  test.setTimeout(8 * 60_000);
  const user = await throwawayUser(api, cleanup, 'qa-login');

  for (let i = 0; i < 5; i += 1) await submitLogin(page, user.email, `wrong-password-${i}`);
  await submitLogin(page, user.email, user.password);
  await expect(page.getByText(/maximum number of login attempts/)).toBeVisible();
  await page.waitForTimeout(305_000);
  await loginThrowaway(page, user);
  await expect(page.getByRole('banner')).toBeVisible();
});

test('Logout – session closed', async ({ page, api, ts, cleanup }) => {
  const user = await throwawayUser(api, cleanup, 'qa-login');
  const info = `QA logout ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));
  await api.createEvent({ info, distribution: 'community' });

  await loginThrowaway(page, user);
  await page.goto('/events/index');
  await expect(page.locator('#tableView').getByText(info, { exact: true })).toBeVisible();
  await logOut(page);

  await page.goBack();
  await page.reload();
  await expect(page).toHaveURL(/\/users\/login/);
  await expect(page.getByText(info)).toHaveCount(0);
  await expect(page.getByLabel('Email')).toBeVisible();
  await expectScreen(loginForm(page), 'account-logout.png');
});
