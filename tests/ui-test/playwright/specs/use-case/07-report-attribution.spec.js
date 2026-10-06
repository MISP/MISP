// ../../../use-case/07-report-attribution.md
const {
  test, expect, expectNoErrorPage, knownBug, openEvent, openTab, row, pick, dialog,
} = require('../../helpers');

test.use({ role: 'orgAdminA' });

test('Use case 7 – Write the report and the attribution', async ({
  page, pageAs, apiAs, api, ts, cleanup,
}) => {
  knownBug('Bug 10 (after saving the report the old event page may open)');
  knownBug('Bug 12 (an empty note is accepted)');
  knownBug('Bug 16 (deep notes are not shown)');
  const info = `Fake-Parcel report ${ts}`;
  const report = 'Fake-Parcel – incident report';
  const event = await apiAs('orgAdminA').createEvent({
    info,
    distribution: 'community',
    attributes: [
      { type: 'domain', category: 'Network activity', value: 'parcel-tracking.example' },
      { type: 'ip-dst', category: 'Network activity', value: '203.0.113.45' },
    ],
  });
  cleanup(() => api.deleteEventsByInfo(info));

  await test.step('Phase 1 – Write the report (org-admin)', async () => {
    await openEvent(page, event.id);
    await page.getByRole('link', { name: 'Add Event Report' }).click();
    const form = dialog(page);
    await form.getByRole('textbox', { name: /descriptive name/ }).fill(report);
    await form.getByRole('textbox', { name: /report content in Markdown/ }).fill(
      '# Summary\nFake parcel emails lead to parcel-tracking.example (203.0.113.45).\n'
      + '## Actions\n- Blocked on the proxy',
    );
    await form.getByRole('button', { name: 'Add Report' }).click();
    await openEvent(page, event.id);
    const reports = await openTab(page, 'Reports');
    await row(reports, report).getByRole('link', { name: /^#\d+$/ }).first().click();
    await expect(page.getByRole('heading', { name: 'Summary' })).toBeVisible();
    await expect(page.getByRole('listitem').filter({ hasText: 'Blocked on the proxy' })).toBeVisible();
  });

  await test.step('Phase 2 – Attribute the campaign', async () => {
    await openEvent(page, event.id);
    await page.getByRole('button', { name: 'Edit Galaxy Clusters' }).click();
    await pick(dialog(page).getByRole('combobox', { name: 'Search clusters to add…' }).first(),
      'APT28', /^APT28 Threat Actor$/);
    await dialog(page).getByRole('button', { name: /^Save/ }).click();
    await expect(page.getByRole('main').getByText('APT28').first()).toBeVisible();
  });

  const lead = await pageAs('siteAdmin');
  await test.step('Phase 3 – Review by the team lead (site-admin)', async () => {
    await openEvent(lead, event.id);
    await lead.getByRole('button', { name: 'Add note' }).click();
    await dialog(lead).getByRole('textbox', { name: 'Write your analysis note…' })
      .fill('Attribution based on infrastructure only, to be confirmed');
    await dialog(lead).getByRole('button', { name: 'Create Note' }).click();
    await expect(dialog(lead)).toHaveCount(0);

    await lead.getByRole('button', { name: 'Add opinion' }).click();
    await expect(dialog(lead).getByRole('slider')).toHaveValue('50');
    await dialog(lead).getByRole('textbox', { name: 'Justify your opinion…' }).fill('Not enough evidence yet');
    await dialog(lead).getByRole('button', { name: 'Create Opinion' }).click();
    await expect(dialog(lead)).toHaveCount(0);

    await lead.reload();
    const analyst = lead.getByRole('tabpanel');
    await expect(analyst.getByText('Attribution based on infrastructure only, to be confirmed')).toBeVisible();
    await expect(analyst.getByText('Not enough evidence yet')).toBeVisible();
    await expectNoErrorPage(lead);
  });

  const saved = await api.getEvent(event.id);
  expect(saved.EventReport.map((r) => r.name)).toContain(report);
  expect(JSON.stringify(saved.Galaxy)).toContain('APT28');
  expect(saved.Note.map((n) => n.note)).toEqual(['Attribution based on infrastructure only, to be confirmed']);
  expect(saved.Opinion.map((o) => [o.opinion, o.comment])).toEqual([['50', 'Not enough evidence yet']]);
});
