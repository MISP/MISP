// ../../../use-case/02-campaign-correlation.md
const {
  test, expect, expectServerOk, blockedBy, addEvent, freetextImport,
  openEvent, openTab, row, dialog,
} = require('../../helpers');

test.use({ role: 'orgAdminA' });

test('Use case 2 – Discover a campaign', async ({ page, apiAs, api, ts, cleanup }) => {
  blockedBy('Bug 3 ("Add sighting" shows "Failed to add sighting")');
  const wave1 = `Fake-Parcel wave 1 ${ts}`;
  const wave2 = `Fake-Parcel wave 2 ${ts}`;
  const first = await apiAs('orgAdminA').createEvent({
    info: wave1,
    distribution: 'community',
    publish: true,
    attributes: [
      { type: 'domain', category: 'Network activity', value: 'parcel-tracking.example' },
      { type: 'ip-dst', category: 'Network activity', value: '203.0.113.45' },
    ],
  });
  cleanup(() => api.deleteEventsByInfo(wave1));
  cleanup(() => api.deleteEventsByInfo(wave2));

  await test.step('Phase 1 – Record the second email', async () => {
    const form = await addEvent(page, { info: wave2, distribution: 'This community only' });
    await form.getByRole('button', { name: 'Create Event Entry' }).click();
    await expect(page.getByRole('heading', { name: wave2, level: 1 })).toBeVisible();
    const review = await freetextImport(page,
      'Redeliver your parcel: hxxp://parcel-tracking[.]example/redeliver from 203.0.113[.]45');
    await review.getByRole('button', { name: 'Create attributes' }).click();
    await expect(dialog(page)).toHaveCount(0);
  });

  await test.step('Phase 2 – Let MISP correlate', async () => {
    await page.reload();
    const correlation = await openTab(page, 'Correlation');
    await expect(correlation.getByRole('link', { name: new RegExp(`^${wave1}`) })).toBeVisible();
    const attributes = await openTab(page, 'Attributes');
    await expect(row(attributes, '203.0.113.45')
      .getByRole('link', { name: `#${first.id}`, exact: true })).toBeVisible();
  });

  await test.step('Phase 3 – Link the two waves', async () => {
    await openTab(page, 'General');
    await page.getByRole('link', { name: 'Edit Event' }).click();
    await dialog(page).getByRole('textbox', { name: 'Extends' }).fill(first.id);
    await dialog(page).getByRole('button', { name: 'Save Changes' }).click();
    await expect(page.getByRole('main').getByRole('link', { name: new RegExp(wave1) }).first())
      .toBeVisible();
  });

  await test.step('Phase 4 – Record what was seen in the logs', async () => {
    const attributes = await openTab(page, 'Attributes');
    await expectServerOk(
      row(attributes, '203.0.113.45').getByRole('button', { name: 'Add sighting' }), '/sightings/add/',
    );
    await expect(page.getByText('Failed to add sighting')).toHaveCount(0);
  });

  const [{ id }] = await api.findEvents(wave2);
  const event = await api.getEvent(id);
  expect(event.extends_uuid).toBe(first.uuid);
  const ip = event.Attribute.find((a) => a.value === '203.0.113.45');
  const sightings = await api.post(`/sightings/listSightings/${ip.id}/attribute`);
  expect(sightings.filter((s) => s.Sighting.type === '0')).toHaveLength(1);
});
