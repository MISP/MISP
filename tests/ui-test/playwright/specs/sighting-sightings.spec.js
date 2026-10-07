// ../../sighting/add/sightings.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, expectServerOk,
  openEvent, openTab, row, dialog, uniqueIp,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function eventWithIp(api, cleanup, info, value) {
  cleanup(() => api.deleteEventsByInfo(info));
  const { id } = await api.createEvent({
    info, distribution: 'community',
    attributes: [{ type: 'ip-dst', category: 'Network activity', value }],
  });
  const event = await api.getEvent(id);
  return { id, attribute: event.Attribute.find((a) => a.value === value) };
}

async function sightingsOf(api, attributeId) {
  return (await api.post(`/sightings/listSightings/${attributeId}/attribute`))
    .map((s) => s.Sighting);
}

async function attributeRow(page, eventId, value) {
  await openEvent(page, eventId);
  return row(await openTab(page, 'Attributes'), value);
}

async function openAdvanced(page, eventId, value) {
  await (await attributeRow(page, eventId, value))
    .getByRole('button', { name: 'Advanced sightings' }).click();
  const panel = dialog(page);
  await expect(panel.getByRole('heading', { name: 'Sightings' })).toBeVisible();
  return panel;
}

test('Sighting – add', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 3 ("Add sighting" shows "Failed to add sighting")');
  const value = uniqueIp(ts);
  const { id, attribute } = await eventWithIp(api, cleanup, `QA sighting add ${ts}`, value);

  const attrRow = await attributeRow(page, id, value);
  await expectServerOk(attrRow.getByRole('button', { name: 'Add sighting' }), '/sightings/add/');
  await expect(page.getByText('Failed to add sighting')).toHaveCount(0);
  const sightings = await sightingsOf(api, attribute.id);
  expect(sightings.filter((s) => s.type === '0')).toHaveLength(1);
  const panel = await openAdvanced(page, id, value);
  await panel.getByRole('tab', { name: 'All' }).click();
  await expect(panel.getByRole('row').filter({ hasText: 'ADMIN' })).toHaveCount(1);
  await expectScreen(panel, 'sighting-add.png');
});

test('Sighting – false positive', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 3 ("Mark as false positive" shows "Failed to add sighting")');
  const value = uniqueIp(ts);
  const { id, attribute } = await eventWithIp(api, cleanup, `QA sighting fp ${ts}`, value);

  const attrRow = await attributeRow(page, id, value);
  await expectServerOk(attrRow.getByRole('button', { name: 'Mark as false positive' }),
    '/sightings/add/');
  const sightings = await sightingsOf(api, attribute.id);
  expect(sightings.filter((s) => s.type === '1')).toHaveLength(1);
  expect(sightings.filter((s) => s.type === '0')).toHaveLength(0);
  await expectScreen(await attributeRow(page, id, value), 'sighting-false-positive.png');
});

test('Sighting – by value in every event', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 3 ("Add sighting" shows "Failed to add sighting")');
  const value = uniqueIp(ts);
  const a = await eventWithIp(api, cleanup, `QA sighting value A ${ts}`, value);
  const b = await eventWithIp(api, cleanup, `QA sighting value B ${ts}`, value);

  await page.goto(`/attributes/index?value=${value}`);
  const rows = page.getByRole('main').getByRole('row').filter({ hasText: value });
  await expect(rows).toHaveCount(2);
  await expectServerOk(rows.first().getByRole('button', { name: 'Add sighting' }), '/sightings/add/');
  expect(await sightingsOf(api, a.attribute.id)).toHaveLength(1);
  expect(await sightingsOf(api, b.attribute.id)).toHaveLength(1);
  await expectScreen(await attributeRow(page, b.id, value), 'sighting-by-value.png');
});

test.describe('as user of QA-Org-B', () => {
  test.use({ role: 'userB' });

  test('Sighting – from another organisation', async ({ page, api, ts, cleanup }) => {
    blockedBy('Bug 3 ("Add sighting" shows "Failed to add sighting")');
    const value = uniqueIp(ts);
    const { id, attribute } = await eventWithIp(api, cleanup, `QA sighting org B ${ts}`, value);
    const orgB = await api.findOrg('QA-Org-B');

    const attrRow = await attributeRow(page, id, value);
    await expectServerOk(attrRow.getByRole('button', { name: 'Add sighting' }), '/sightings/add/');
    const sightings = await sightingsOf(api, attribute.id);
    expect(sightings.map((s) => String(s.org_id))).toEqual([String(orgB.id)]);
    await expectScreen(await attributeRow(page, id, value), 'sighting-other-org.png');
  });
});

test('Sighting – date in the future', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 3 (Advanced sightings answers an error 400 with only "{}")');
  const value = uniqueIp(ts);
  const { id, attribute } = await eventWithIp(api, cleanup, `QA sighting future ${ts}`, value);
  const nextYear = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString().slice(0, 10);

  const panel = await openAdvanced(page, id, value);
  await panel.getByRole('tab', { name: 'Add sighting' }).click();
  await panel.locator('input[name="date"]').fill(nextYear);
  await expectServerOk(panel.getByRole('button', { name: 'Add', exact: true }), '/sightings/add/');
  const sightings = await sightingsOf(api, attribute.id);
  const now = Date.now() / 1000 + 3600;
  expect(sightings.filter((s) => Number(s.date_sighting) > now)).toHaveLength(0);
  await expectScreen(panel, 'sighting-future.png');
});

test('Sighting – delete', async ({ page, api, ts, cleanup }) => {
  const value = uniqueIp(ts);
  const { id, attribute } = await eventWithIp(api, cleanup, `QA sighting delete ${ts}`, value);
  await api.post('/sightings/add', { id: attribute.id, type: 0 });
  await api.post('/sightings/add', { id: attribute.id, type: 0 });

  const panel = await openAdvanced(page, id, value);
  await panel.getByRole('tab', { name: 'All' }).click();
  const listed = panel.getByRole('row').filter({ has: page.getByRole('button', { name: 'Delete sighting' }) });
  await expect(listed).toHaveCount(2);
  await listed.first().getByRole('button', { name: 'Delete sighting' }).click();
  const confirm = dialog(page);
  await expect(confirm.getByRole('heading', { name: 'Delete sighting' })).toBeVisible();
  blockedBy('New bug: deleting a sighting is black-holed (/sightings/quickDelete has no form '
    + 'token, as in Bug 3)');
  await expectServerOk(confirm.getByRole('button', { name: 'Delete', exact: true }), '/sightings/');
  await expect.poll(async () => (await sightingsOf(api, attribute.id)).length).toBe(1);
  await expectNoErrorPage(page);
  await expectScreen(await attributeRow(page, id, value), 'sighting-delete.png');
});

test('Sightings card – full list button', async ({ page, api, ts, cleanup }) => {
  const value = uniqueIp(ts);
  const { id, attribute } = await eventWithIp(api, cleanup, `QA sightings card ${ts}`, value);
  // Seeded through the API: the UI button is Bug 3, and Bug 25 happens with or without sightings.
  await api.post('/sightings/add', { id: attribute.id, type: 0 });

  await openEvent(page, id);
  const card = page.locator('#sightings-card');
  await expect(card.getByText('1 sightings')).toBeVisible();
  blockedBy('Bug 25 (the "Full sightings list" button reloads the same event page)');
  await card.getByRole('link', { name: 'Full sightings list' }).click();
  await expect(page).not.toHaveURL(new RegExp(`/events/view2/${id}$`));
  await expect(page.getByText(value)).toBeVisible();
  await expectScreen(page.getByRole('main'), 'sighting-card-full-list.png');
});

test('Advanced sightings – empty form', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 3 (Advanced sightings answers an error 400 with only "{}")');
  const value = uniqueIp(ts);
  const { id, attribute } = await eventWithIp(api, cleanup, `QA advanced sighting ${ts}`, value);

  const panel = await openAdvanced(page, id, value);
  await panel.getByRole('tab', { name: 'Add sighting' }).click();
  await expectServerOk(panel.getByRole('button', { name: 'Add', exact: true }), '/sightings/add/');
  await expect(panel.getByText('{}', { exact: true })).toHaveCount(0);
  expect(await sightingsOf(api, attribute.id)).toHaveLength(1);
  await expectScreen(panel, 'sighting-advanced-empty.png');
});
