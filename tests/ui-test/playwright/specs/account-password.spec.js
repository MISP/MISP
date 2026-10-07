// ../../account/password/password.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen,
  throwawayUser, submitLogin, loginThrowaway,
} = require('../helpers');

// A throwaway "User" of ADMIN: the QA accounts keep their passwords.
test.use({ storageState: { cookies: [], origins: [] } });

// My Profile -> Edit profile -> Set a new password.
async function changePassword(page, current, password, confirm = password) {
  await page.goto('/users/view/me');
  await page.getByRole('link', { name: 'Edit profile' }).click();
  await page.getByRole('switch', { name: /^Set a new password/ }).check();
  await page.locator('#profilePassword').fill(password);
  await page.locator('#profileConfirm').fill(confirm);
  await page.locator('#profileCurrentPassword').fill(current);
  await page.getByRole('button', { name: 'Save changes' }).click();
}

// Logs in from a new browser with `password`.
async function expectLoginWorks(browser, email, password) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();
  await submitLogin(page, email, password);
  await expect(page).not.toHaveURL(/\/users\/login/);
  await context.close();
}

test('Password – too short', async ({ page, browser, api, cleanup }) => {
  const user = await throwawayUser(api, cleanup, 'qa-password');
  await loginThrowaway(page, user);

  await changePassword(page, user.password, 'short');
  await expectNoErrorPage(page);
  await expect(page.getByText('The profile could not be updated.')).toBeVisible();
  await expectLoginWorks(browser, user.email, user.password);
  blockedBy('Recommendation 3 (a too short password is refused without saying why)');
  await expect(page.getByText(/Password length requirement not met|too short/i).first())
    .toBeVisible();
  await expectScreen(page.getByRole('main'), 'account-password-short.png');
});

test('Password – long without complexity', async ({ page, browser, api, cleanup }) => {
  const user = await throwawayUser(api, cleanup, 'qa-password');
  const longPassword = 'qalonglowercasepass';
  await loginThrowaway(page, user);

  await changePassword(page, user.password, longPassword);
  await expectNoErrorPage(page);
  await expect(page).not.toHaveURL(/\/users\/edit/);
  await expectLoginWorks(browser, user.email, longPassword);
  await expectScreen(page.getByRole('main'), 'account-password-long.png');
});

test('Password – wrong confirmation', async ({ page, browser, api, cleanup }) => {
  const user = await throwawayUser(api, cleanup, 'qa-password');
  await loginThrowaway(page, user);

  await changePassword(page, user.password, 'QaNewPassword-2026!', 'QaOtherPassword-2026!');
  await expectNoErrorPage(page);
  await expect(page.getByText('The profile could not be updated.')).toBeVisible();
  await expectLoginWorks(browser, user.email, user.password);
  blockedBy('Recommendation 3 (a wrong confirmation is refused without saying why)');
  await expect(page.getByText(/do not match|does not match/i).first()).toBeVisible();
  await expectScreen(page.getByRole('main'), 'account-password-confirm.png');
});
