// ../../event/view/performance.md
const {
  test, expect, expectNoErrorPage, expectScreen, openTab, row,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

test('Event view – event with 2,000 attributes', async ({ page, api, ts, cleanup }) => {
  test.setTimeout(180_000);
  const event = await api.createEvent({ info: `QA big event ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));
  const values = ['198.51.100.250', ...Array.from({ length: 1999 }, (_, i) => `10.${i >> 8}.${i & 255}.1`)];
  await api.post(`/attributes/add/${event.id}`,
    values.map((value) => ({ type: 'ip-dst', category: 'Network activity', value, to_ids: false })));

  const start = Date.now();
  await page.goto(`/events/view2/${event.id}`);
  const attributes = await openTab(page, 'Attributes');
  await expect(attributes.getByRole('row').nth(1)).toBeVisible();
  const elapsed = Date.now() - start;
  test.info().annotations.push({ type: 'attribute list shown after', description: `${elapsed} ms` });
  expect(elapsed, 'attribute list shown in less than 5 s').toBeLessThan(5_000);

  await attributes.getByRole('navigation', { name: 'Pagination' }).first()
    .getByRole('link', { name: '2', exact: true }).click();
  await expect(attributes.getByText(/Page 2 of/)).toBeVisible();

  const search = attributes.getByRole('textbox', { name: /Filter by attribute value/ });
  await search.fill('198.51.100.250');
  await search.press('Enter');
  await expect(row(page.getByRole('tabpanel').filter({ visible: true }), '198.51.100.250')).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(row(page.getByRole('tabpanel').filter({ visible: true }), '198.51.100.250'),
    'event-view-big-event-search.png');
});
