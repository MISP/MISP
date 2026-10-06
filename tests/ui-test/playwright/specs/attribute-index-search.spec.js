// ../../attribute/index/search.md
const {
  test, expect, expectNoErrorPage, expectScreen, pick,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const main = (page) => page.getByRole('main');
const ip = (value) => ({ type: 'ip-dst', category: 'Network activity', value });

async function search(page, text) {
  await page.goto('/attributes/index');
  const box = page.getByRole('textbox', { name: /Filter by attribute value/ });
  await box.fill(text);
  await box.press('Enter');
}

test('Attribute list – filter by value', async ({ page, api, ts, cleanup }) => {
  const events = [];
  for (const n of [1, 2]) {
    const event = await api.createEvent({ info: `QA delete correlation ${n} ${ts}`, attributes: [ip('198.51.100.51')] });
    cleanup(() => api.deleteEventsByInfo(event.info));
    events.push(event);
  }

  await search(page, '198.51.100.51');

  const rows = main(page).getByRole('row').filter({ hasText: '198.51.100.51' });
  for (const event of events) {
    await expect(rows.filter({ has: page.getByRole('cell', { name: `#${event.id}`, exact: true }) }))
      .toHaveCount(1);
  }
  await expectScreen(main(page).getByRole('table'), 'attribute-index-filter-value.png');
});

test('Attribute list – filter by type', async ({ page }) => {
  await page.goto('/attributes/index');
  await page.getByRole('button', { name: 'More filters' }).click();
  await pick(page.locator('select[name=type] + .ts-wrapper').getByRole('combobox'), 'ip-dst');
  await page.getByRole('button', { name: 'Apply filters' }).click();

  await expect(page).toHaveURL(/type/);
  const types = await main(page).locator('tbody tr').evaluateAll((rows) => rows
    .map((r) => [...r.querySelectorAll('td')].map((td) => td.innerText.trim()))
    .map((cells) => cells.find((t) => /^[a-z0-9|-]+$/.test(t) && !/^\d/.test(t))));
  expect(types.length).toBeGreaterThan(0);
  expect(new Set(types)).toEqual(new Set(['ip-dst']));
  await expectScreen(main(page).getByRole('table').getByRole('row').first(), 'attribute-index-filter-type.png');
});

test('Attribute list – special characters', async ({ page }) => {
  const text = '\'%"<b>';
  await search(page, text);

  await expectNoErrorPage(page);
  await expect(page.getByRole('textbox', { name: /Filter by attribute value/ })).toHaveValue(text);
  for (const line of await main(page).locator('tbody tr').allInnerTexts()) expect(line).toContain(text);
  await expectScreen(main(page), 'attribute-index-special-chars.png');
});
