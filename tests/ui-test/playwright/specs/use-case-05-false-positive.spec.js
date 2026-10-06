// ../../use-case/05-false-positive.md
const {
  test, expect, expectServerOk, blockedBy, openEvent, openTab, row, rowAction, dialog,
  expectScreen,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const DNS_LIST = 'List of known IPv4 public DNS resolvers';

test('Use case 5 – Handle a false positive', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 3 ("Mark as false positive" shows "Failed to add sighting")');
  const info = `Fake-Parcel false positive ${ts}`;
  const event = await api.createEvent({
    info,
    attributes: [
      { type: 'ip-dst', category: 'Network activity', value: '203.0.113.45', to_ids: true },
      { type: 'ip-dst', category: 'Network activity', value: '8.8.8.8', to_ids: true },
    ],
  });
  cleanup(() => api.deleteEventsByInfo(info));
  cleanup(() => api.deleteCorrelationExclusion('8.8.8.8'));
  cleanup(await api.enableWarninglist(DNS_LIST));

  await test.step('Phase 1 – MISP warns', async () => {
    await page.goto('/warninglists/index');
    const search = page.getByRole('textbox', { name: 'Search by warninglist name' });
    await search.fill(DNS_LIST);
    await search.press('Enter');
    await expect(row(page.getByRole('main'), DNS_LIST).getByRole('cell', { name: 'Enabled', exact: true }))
      .toBeVisible();

    // Overmind lists the warninglist hits in the "Warning Lists" panel of the event.
    await openEvent(page, event.id);
    await expect(page.getByRole('tabpanel').getByRole('link', { name: DNS_LIST })).toBeVisible();
  });

  await test.step('Phase 2 – Mark it as a false positive', async () => {
    const attributes = await openTab(page, 'Attributes');
    await expectServerOk(
      row(attributes, '8.8.8.8').getByRole('button', { name: 'Mark as false positive' }), '/sightings/add/',
    );
  });

  await test.step('Phase 3 – Keep it out of the defence tools and correlations', async () => {
    const attributes = await openTab(page, 'Attributes');
    await rowAction(row(attributes, '8.8.8.8'), 'Edit');
    await dialog(page).getByRole('checkbox', { name: /^For IDS/ }).uncheck();
    await dialog(page).getByRole('button', { name: 'Save Changes' }).click();
    const updated = page.getByRole('tabpanel').filter({ visible: true });
    await expect(row(updated, '8.8.8.8').getByRole('button', { name: /^IDS inactive/ })).toBeVisible();
    await expect(row(updated, '203.0.113.45').getByRole('button', { name: /^IDS active/ })).toBeVisible();

    await page.goto('/correlation_exclusions/index');
    await page.getByRole('link', { name: 'Add correlation exclusion entry' }).click();
    await dialog(page).getByRole('textbox', { name: '8.8.8.8' }).fill('8.8.8.8');
    await dialog(page).getByRole('textbox', { name: /Why this value/ }).fill('Public DNS, false positive');
    await dialog(page).getByRole('button', { name: 'Add Exclusion' }).click();
    await expect(row(page.getByRole('main'), '8.8.8.8')).toBeVisible();
  });
  await expectScreen(row(page.getByRole('main'), '8.8.8.8'), 'use-case-5-exclusion.png');
});
