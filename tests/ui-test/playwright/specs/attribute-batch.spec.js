// ../../attribute/add/batch.md
const {
  test, expect, expectNoErrorPage, expectScreen, fillAttribute, submitAttribute,
  openEvent, openTab, row,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

// Batch Import of ip-dst values (one per line) on a new event; returns it.
async function batch(page, api, cleanup, info, lines) {
  const event = await api.createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));
  await openEvent(page, event.id);
  const form = await fillAttribute(page, {
    category: 'Network activity', type: 'ip-dst', value: lines.join('\n'), batch: true,
  });
  await submitAttribute(form);
  await expect(form).toBeHidden();
  return event;
}

const values = async (api, event) => (await api.getEvent(event.id)).Attribute.map((a) => a.value).sort();
const flash = (page) => page.locator('.alert, .toast, [role=alert]').filter({ visible: true }).first();

test('Batch import – valid values', async ({ page, api, ts, cleanup }) => {
  const ips = ['198.51.100.40', '198.51.100.41', '198.51.100.42'];
  const event = await batch(page, api, cleanup, `QA batch valid ${ts}`, ips);

  expect(await values(api, event)).toEqual(ips);
  const attributes = await openTab(page, 'Attributes');
  for (const ip of ips) await expect(row(attributes, ip)).toBeVisible();
  await expectScreen(attributes.getByRole('table'), 'attribute-batch-valid.png');
});

test('Batch import – some invalid values', async ({ page, api, ts, cleanup }) => {
  const event = await batch(page, api, cleanup, `QA batch partial ${ts}`,
    ['198.51.100.43', '999.1.1.1', '198.51.100.44']);

  expect(await values(api, event)).toEqual(['198.51.100.43', '198.51.100.44']);
  await expect(flash(page)).toContainText(/1 attribute.*could not be saved/i);
  await expect(page.getByText('$flashErrorMessage')).toHaveCount(0);
  const more = flash(page).getByRole('link');
  await expect(more.first()).toHaveAttribute('href', /.+/);
  await expectScreen(flash(page), 'attribute-batch-partial.png');
});

test('Batch import – empty lines and spaces', async ({ page, api, ts, cleanup }) => {
  const event = await batch(page, api, cleanup, `QA batch blank ${ts}`,
    ['198.51.100.45', '', '   ', '198.51.100.46']);

  expect(await values(api, event)).toEqual(['198.51.100.45', '198.51.100.46']);
  await expectNoErrorPage(page);
  await expectScreen((await openTab(page, 'Attributes')).getByRole('table'), 'attribute-batch-blank-lines.png');
});

test('Batch import – same value twice', async ({ page, api, ts, cleanup }) => {
  const event = await batch(page, api, cleanup, `QA batch duplicates ${ts}`,
    ['198.51.100.47', '198.51.100.47']);

  expect(await values(api, event)).toEqual(['198.51.100.47']);
  await expect(flash(page)).toContainText(/1 attribute.*could not be saved|already exists|duplicate/i);
  await expectScreen(flash(page), 'attribute-batch-duplicates.png');
});
