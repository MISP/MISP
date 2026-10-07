// ../../use-case/01-phishing-triage.md
const {
  test, expect, expectNoErrorPage, expectDialogSaved, blockedBy, addEvent, freetextImport, freetextResults,
  openTab, row, pick, chooseSlider, dialog, expectAfterReload,
  expectScreen,
  eventSummary,
} = require('../helpers');

test.use({ role: 'orgAdminA' });

test('Use case 1 – Triage a phishing email', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 4 (saving an object is black-holed when the user can see no sharing group: the empty Sharing group field breaks the form token)');
  const info = `Fake-Parcel phishing ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));

  await test.step('Phase 1 – Create the event', async () => {
    const form = await addEvent(page, { info, distribution: 'This community only' });
    await chooseSlider(form, 'Threat level', 'Medium');
    await chooseSlider(form, 'Analysis level', 'Initial');
    await form.getByRole('button', { name: 'Create Event Entry' }).click();
    await expect(page).toHaveURL(/\/events\/view2\/\d+/);
    await expect(page.getByRole('heading', { name: info, level: 1 })).toBeVisible();
  });

  await test.step('Phase 2 – Record the email', async () => {
    await page.getByRole('link', { name: 'Add Object' }).click();
    await pick(dialog(page).getByRole('combobox', { name: /Template/ }), 'email', /^Email v\d/);
    await dialog(page).getByRole('button', { name: 'Next' }).click();
    const form = dialog(page);
    await form.getByRole('button', { name: /^From email-src/ }).click();
    await form.getByRole('button', { name: /^Subject email-subject/ }).click();
    await form.locator('.attribute_row[data-object-relation="from"] textarea.Attribute_value')
      .fill('delivery@parcel-tracking.example');
    await form.locator('.attribute_row[data-object-relation="subject"] textarea.Attribute_value')
      .fill('Your parcel could not be delivered');
    await form.getByRole('button', { name: 'Review', exact: true }).filter({ visible: true }).first().click();
    await form.getByRole('button', { name: 'Add Object' }).click();
    await expectDialogSaved(page);
    const objects = await openTab(page, 'Objects');
    await expect(objects.getByText('delivery@parcel-tracking.example').first()).toBeVisible();
    await expect(objects.getByText('Your parcel could not be delivered').first()).toBeVisible();
  });

  await test.step('Phase 3 – Extract the indicators from the email text', async () => {
    const review = await freetextImport(page, 'Dear customer, track your parcel at '
      + 'hxxp://parcel-tracking[.]example/track?id=48213 . Our server 203.0.113[.]45 will keep it 48h.');
    expect(await freetextResults(review)).toEqual([
      ['http://parcel-tracking.example/track?id=48213', 'url'],
      ['203.0.113.45', 'ip-dst'],
    ]);
    await review.getByRole('button', { name: 'Create attributes' }).click();
    await expect(dialog(page)).toHaveCount(0);
    const attributes = await openTab(page, 'Attributes');
    for (const value of ['http://parcel-tracking.example/track?id=48213', '203.0.113.45']) {
      await expect(row(attributes, value)).toBeVisible();
    }
  });

  await test.step('Phase 4 – Classify', async () => {
    await openTab(page, 'General');
    await page.getByRole('button', { name: 'Edit Tags' }).click();
    await pick(dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first(), 'tlp:amber');
    await dialog(page).getByRole('button', { name: 'Save Tags' }).click();
    await page.getByRole('button', { name: 'Edit Galaxy Clusters' }).click();
    await pick(dialog(page).getByRole('combobox', { name: 'Search clusters to add…' }).first(),
      'Phishing - T1566', /^Phishing - T1566 /);
    await dialog(page).getByRole('button', { name: /^Save/ }).click();
    await expect(page.getByRole('main').getByText('tlp:amber').first()).toBeVisible();
    await expect(page.getByRole('main').getByText('Phishing - T1566').first()).toBeVisible();
  });

  await test.step('Phase 5 – Publish', async () => {
    await page.getByRole('link', { name: 'Publish Event' }).click();
    await dialog(page).getByRole('button', { name: 'Publish', exact: true }).click();
    await expectAfterReload(page,
      () => expect(page.getByRole('main')).toContainText(/Publication\s*Published/));
  });

  const [{ id }] = await api.findEvents(info);
  const event = await api.getEvent(id);
  expect(event.distribution).toBe('1');
  expect(event.threat_level_id).toBe('2');
  expect(event.published).toBe(true);
  expect(event.Attribute.map((a) => [a.value, a.type])).toEqual(expect.arrayContaining([
    ['http://parcel-tracking.example/track?id=48213', 'url'],
    ['203.0.113.45', 'ip-dst'],
  ]));
  expect(event.Tag.map((t) => t.name)).toContain('tlp:amber');
  expect(JSON.stringify(event.Galaxy)).toContain('Phishing - T1566');
  expect((event.Object || []).map((o) => o.name)).toContain('email');
  await expectNoErrorPage(page);
  await expectScreen(eventSummary(page), 'use-case-1-published-event.png');
});
