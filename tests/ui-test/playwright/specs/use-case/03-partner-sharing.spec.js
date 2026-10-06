// ../../../use-case/03-partner-sharing.md
const {
  test, expect, expectServerOk, expectScreen, blockedBy, openEvent, openTab, row, rowAction, pick, dialog,
} = require('../../helpers');

test.use({ role: 'orgAdminA' });

test('Use case 3 – Share with a partner CERT', async ({ page, pageAs, apiAs, api, ts, cleanup }) => {
  blockedBy('Bug 3 ("Add sighting" shows "Failed to add sighting"); '
    + 'new bug: "Accept proposal" on the event page is black-holed');
  const info = `Fake-Parcel shared ${ts}`;
  const group = `QA Fake-Parcel partners ${ts}`;
  const event = await apiAs('orgAdminA').createEvent({
    info,
    distribution: 'org',
    attributes: [{ type: 'ip-dst', category: 'Network activity', value: '203.0.113.45' }],
  });
  cleanup(() => api.deleteSharingGroupByName(group));
  cleanup(() => api.deleteEventsByInfo(info));

  await test.step('Phase 1 – Create the sharing group', async () => {
    await page.goto('/sharing_groups/index');
    await page.getByRole('link', { name: 'Add SharingGroups' }).click();
    const form = dialog(page);
    await expectScreen(form, 'add-sharing-group-dialog.png');
    await form.getByRole('textbox', { name: 'e.g. Multinational sharing group' }).fill(group);
    await form.getByRole('textbox', { name: /e\.g\. Community1/ }).fill('QA');
    await form.getByRole('button', { name: '2 Organisations' }).click();
    await pick(form.getByRole('combobox', { name: 'Search local organisations…' }), 'QA-Org-B');
    await expect(form.getByRole('cell', { name: 'QA-Org-B', exact: true })).toBeVisible();
    await form.getByRole('button', { name: 'Add Sharing Group' }).click();
    await expect.poll(() => api.findSharingGroup(group)).toBeTruthy();
  });

  await test.step('Phase 2 – Share the event', async () => {
    await openEvent(page, event.id);
    await page.getByRole('link', { name: 'Edit Event' }).click();
    const form = dialog(page);
    await form.getByRole('radio', { name: /^Sharing group/ }).check();
    await pick(form.locator('select[name*="sharing_group_id"] + .ts-wrapper').getByRole('combobox'), group);
    await form.getByRole('button', { name: 'Save Changes' }).click();
    await page.getByRole('link', { name: 'Publish Event' }).click();
    await dialog(page).getByRole('button', { name: 'Publish', exact: true }).click();
    await expect(page.getByText('Job queued')).toBeVisible();
  });

  const partner = await pageAs('userB');
  await test.step('Phase 3 – The partner works on it (user of QA-Org-B)', async () => {
    await partner.goto('/events/index');
    await expect(row(partner.getByRole('main'), info)).toBeVisible();
    await openEvent(partner, event.id);
    const attributes = await openTab(partner, 'Attributes');
    await expectServerOk(
      row(attributes, '203.0.113.45').getByRole('button', { name: 'Add sighting' }), '/sightings/add/',
    );
    await rowAction(row(attributes, '203.0.113.45'), 'Propose change');
    await dialog(partner).getByRole('textbox').first().fill('203.0.113.47');
    await dialog(partner).getByRole('button', { name: 'Submit proposal' }).click();
    await expect(dialog(partner)).toHaveCount(0);
    await expect(row(await openTab(partner, 'Attributes'), '203.0.113.45')).toBeVisible();
  });

  await test.step('Phase 4 – The CERT reviews (org-admin of ADMIN)', async () => {
    await page.goto('/shadow_attributes/index/all:0');
    await expect(row(page.getByRole('main'), '203.0.113.47').filter({ hasText: info }))
      .toContainText('QA-Org-B');
    await openEvent(page, event.id);
    const attributes = await openTab(page, 'Attributes');
    await attributes.getByRole('link', { name: /^Proposals/ }).click();
    await expectServerOk(page.getByRole('tabpanel').filter({ visible: true })
      .getByRole('button', { name: 'Accept proposal' }), '/shadow_attributes/accept/');
  });

  const saved = await api.getEvent(event.id);
  expect(saved.Attribute.map((a) => a.value)).toEqual(['203.0.113.47']);
});
