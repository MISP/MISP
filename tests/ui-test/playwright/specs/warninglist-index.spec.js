// ../../warninglist/index/filters.md
const {
  test, expect, blockedBy, expectScreen, pick, row, rowAction, dialog,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const main = (page) => page.getByRole('main');
const DNS_LIST = 'List of known IPv4 public DNS resolvers';

async function filterOn(page, field, option) {
  await page.goto('/warninglists/index');
  await page.getByRole('button', { name: 'More filters' }).click();
  await pick(page.locator(`select[name=${field}] + .ts-wrapper`).getByRole('combobox'), option, new RegExp(`^${option}$`));
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page).toHaveURL(new RegExp(`${field}`));
}

const listedNames = (page) => main(page).locator('tbody tr').evaluateAll((rows) => rows
  .map((r) => r.querySelector('td:nth-child(3) p, td:nth-child(3)')?.innerText.trim()).filter(Boolean));

test('Warninglist list – Default filter', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 21 (the "Default" filter of the Warninglists list is ignored)');
  const name = `QA custom warninglist ${ts}`;
  cleanup(() => api.deleteWarninglistByName(name));

  await page.goto('/warninglists/index');
  await page.getByRole('link', { name: 'Add Warninglist' }).click();
  const form = dialog(page);
  await form.getByRole('textbox', { name: 'e.g. Known public DNS resolvers' }).fill(name);
  await form.getByRole('textbox', { name: 'What this list contains and why a hit matters…' }).fill('QA test data');
  await form.getByRole('textbox', { name: /8\.8\.8\.8/ }).fill('qa-warning.example');
  await form.getByRole('button', { name: 'Add Warninglist' }).click();
  await expect.poll(() => api.findWarninglist(name)).toBeTruthy();

  await filterOn(page, 'default', 'Not default');
  const names = await listedNames(page);
  expect(names.some((n) => n.startsWith(name))).toBe(true);
  expect(names.filter((n) => !n.startsWith('QA custom warninglist')), 'only custom warninglists').toEqual([]);
  await expectScreen(row(main(page), name), 'warninglist-index-default-filter.png', { hide: [ts] });
});

test('Warninglist list – Enabled filter', async ({ page, api, cleanup }) => {
  const restore = await api.enableWarninglist(DNS_LIST);
  cleanup(restore);

  await filterOn(page, 'enabled', 'Enabled');
  // Many warninglists are enabled on an instance: every listed one must be,
  // and the DNS list must be among them (searched by name, the filter kept).
  const lists = main(page).locator('tbody tr').filter({ has: page.getByRole('link', { name: /^#\d+$/ }) });
  const count = await lists.count();
  expect(count).toBeGreaterThan(0);
  // The state is an icon titled "Enabled" in the Enabled column.
  const enabled = lists.locator('td:nth-child(8) i[title="Enabled"]');
  await expect(enabled).toHaveCount(count);
  const search = page.getByRole('textbox', { name: 'Search by warninglist name' });
  await search.fill(DNS_LIST);
  await search.press('Enter');
  await expect(page).toHaveURL(/enabled/);
  await expect(row(main(page), DNS_LIST)).toBeVisible();
  await expectScreen(row(main(page), DNS_LIST), 'warninglist-index-enabled-filter.png');
});
