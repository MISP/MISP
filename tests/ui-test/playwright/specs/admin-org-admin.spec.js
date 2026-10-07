// ../../admin/users/org-admin.md
const {
  test, expect, expectNoErrorPage, expectScreen,
} = require('../helpers');
const { credentials } = require('../harness/env');

test.use({ role: 'orgAdminB' });

test('Org Admin – users list', async ({ page }) => {
  await page.goto('/admin/users/index');
  const main = page.getByRole('main');
  const emails = main.locator('tbody').getByText(/@/);
  await expect(emails.first()).toBeVisible();
  const listed = (await emails.allInnerTexts()).map((t) => t.trim()).sort();
  expect(listed).toEqual([credentials('orgAdminB').email, credentials('userB').email].sort());
  await expectNoErrorPage(page);
  await expectScreen(main.locator('table'), 'admin-orgadmin-users-list.png');
});

test('Org Admin – user of another organisation', async ({ page, api }) => {
  const { id } = await api.findUser(credentials('userA').email);
  await page.goto('/admin/users/index');
  await page.goto(`/admin/users/edit/${id}`);
  await expect(page.getByText('Invalid user')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save changes' })).toHaveCount(0);
  await expect(page.locator('#UserEmail')).toHaveCount(0);
  await expectScreen(page.getByText('Invalid user'), 'admin-orgadmin-edit-other-org.png');
});
