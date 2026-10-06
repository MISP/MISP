// ../../use-case/08-close-incident.md
const {
  test, expect, expectNoErrorPage, knownBug, openEvent, openTab, row, rowAction, chooseSlider,
  dialog, expectAfterReload,
  expectScreen,
  eventSummary,
} = require('../helpers');

test.use({ role: 'orgAdminA' });

test('Use case 8 – Close the incident', async ({ page, apiAs, api, ts, cleanup }) => {
  knownBug('Bug 9 (Unpublish Event may open the old event page)');
  const info = `Fake-Parcel closing ${ts}`;
  const event = await apiAs('orgAdminA').createEvent({
    info,
    analysis: 1,
    publish: true,
    attributes: [
      { type: 'domain', category: 'Network activity', value: 'parcel-tracking.example' },
      { type: 'ip-dst', category: 'Network activity', value: '203.0.113.99' },
    ],
  });
  cleanup(() => api.deleteEventsByInfo(info));

  await test.step('Phase 1 – Remove the wrong indicator', async () => {
    await openEvent(page, event.id);
    let attributes = await openTab(page, 'Attributes');
    await rowAction(row(attributes, '203.0.113.99'), 'Delete');
    await dialog(page).getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(row(attributes, '203.0.113.99')).toHaveCount(0);
    await attributes.getByRole('link', { name: /^Deleted/ }).click();
    attributes = page.getByRole('tabpanel').filter({ visible: true });
    await expect(row(attributes, '203.0.113.99')).toBeVisible();
    await rowAction(row(attributes, '203.0.113.99'), 'Restore');
    await dialog(page).getByRole('button', { name: 'Restore', exact: true }).click();
    await expect(dialog(page)).toHaveCount(0);
    await attributes.getByRole('link', { name: /^Deleted/ }).click();
    attributes = page.getByRole('tabpanel').filter({ visible: true });
    await rowAction(row(attributes, '203.0.113.99'), 'Delete');
    await dialog(page).getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(row(attributes, '203.0.113.99')).toHaveCount(0);
  });

  await test.step('Phase 2 – Complete the analysis', async () => {
    await openEvent(page, event.id);
    await page.getByRole('link', { name: 'Edit Event' }).click();
    await chooseSlider(dialog(page), 'Analysis level', 'Completed');
    await dialog(page).getByRole('button', { name: 'Save Changes' }).click();
    await expect(page.getByRole('main')).toContainText(/Publication\s*Unpublished/);
    await page.getByRole('link', { name: 'Publish Event' }).click();
    await dialog(page).getByRole('button', { name: 'Publish', exact: true }).click();
    await expectAfterReload(page,
      () => expect(page.getByRole('main')).toContainText(/Publication\s*Published/));
  });

  await test.step('Phase 3 – Check the history', async () => {
    const history = await openTab(page, 'History');
    // Each entry reads "<action> <model> <label>"; the words are separate elements.
    await expect(history).toContainText(/Soft delete\s*Attribute.*?203\.0\.113\.99/);
    await expect(history).toContainText(/Undelete\s*Attribute.*?203\.0\.113\.99/);
    await expect(history).toContainText(new RegExp(`Edit\\s*Event\\s*${info}`));
    await expect(history).toContainText(new RegExp(`Publish\\s*Event\\s*${info}`));
    await expectNoErrorPage(page);
  });

  const saved = await api.getEvent(event.id);
  expect(saved.published).toBe(true);
  expect(saved.analysis).toBe('2');
  const ip = (await api.post('/attributes/restSearch', { eventid: event.id, deleted: 1 }))
    .response.Attribute.find((a) => a.value === '203.0.113.99');
  expect(ip.deleted).toBe(true);
  await openEvent(page, event.id);
    await expectScreen(eventSummary(page), 'use-case-8-closed-event.png');
});
