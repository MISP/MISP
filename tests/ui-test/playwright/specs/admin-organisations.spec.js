// ../../admin/organisations/organisations.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, dialog, row,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

test('Organisation delete – still used', async ({ page, api }) => {
  await page.goto('/organisations/index');
  await row(page.getByRole('main'), 'QA-Org-B').locator('button').last().click();
  await page.locator('.dropdown-menu.show').getByRole('link', { name: 'Delete', exact: true }).click();
  const box = dialog(page);
  await expect(box.getByRole('heading', { name: 'Deletion not possible' })).toBeVisible();
  await expect(box.getByRole('alert')).toContainText(/still has \d+ user\(s\)/);
  await expect(box.getByRole('button', { name: /delete|confirm/i })).toHaveCount(0);
  await api.findOrg('QA-Org-B');
  await expectNoErrorPage(page);
  await expectScreen(box, 'admin-org-delete-used.png');
});

test('Organisation add – emoji in the name', async ({ page, api, ts, cleanup }) => {
  const name = `QA Org 🚀 ${ts}`;
  cleanup(() => api.deleteOrgByName(name));
  blockedBy('Bug 5 (an emoji in an organisation name gives "An Internal Error Has Occurred.")');

  await page.goto('/organisations/index');
  await page.getByRole('main').getByRole('link', { name: 'Add organisation' }).click();
  const form = dialog(page);
  await form.getByRole('textbox', { name: 'Organisation identifier' }).fill(name);
  await form.getByRole('button', { name: 'Add organisation' }).click();
  await expectNoErrorPage(page);
  const orgs = (await api.get('/organisations/index/scope:all')).map((o) => o.Organisation);
  expect(orgs.map((o) => o.name)).toContain(name);
  await page.goto('/organisations/index');
  await expect(row(page.getByRole('main'), name)).toBeVisible();
  await expectScreen(row(page.getByRole('main'), name), 'admin-org-emoji.png');
});
