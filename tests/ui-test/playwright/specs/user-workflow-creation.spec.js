// ../../user-workflow/creation.md
const {
  test, expect, expectNoErrorPage, expectDialogSaved, expectScreen, knownBug, blockedBy, openEvent, openTab, row, rowAction, pick, dialog,
  expectAfterReload, freetextImport, freetextResults,
  eventSummary,
  eventCard,
} = require('../helpers');

test.use({ role: 'userA' });

test('Event creation – info, date, distribution', async ({ page, api, ts, cleanup }) => {
  const info = `QA wf create ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));

  await page.goto('/events/index');
  await page.getByRole('link', { name: 'Add Event' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('textbox', { name: /Event Info/ }).fill(info);
  await dialog.getByRole('textbox', { name: /Event Date/ }).fill('15/09/2026');
  await dialog.getByRole('radio', { name: /^This community only/ }).check();
  await dialog.getByRole('button', { name: 'Create Event Entry' }).click();

  await expect(page).toHaveURL(/\/events\/view2\/\d+/);
  await expect(page.getByRole('heading', { name: info, level: 1 })).toBeVisible();
  const main = page.getByRole('main');
  await expect(main.getByText('2026-09-15', { exact: true })).toBeVisible();
  await expect(main.getByText('This community only', { exact: true })).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(eventSummary(page), 'wf-event-create.png');
});

test('Add object – IDS and correlation on one attribute, and a relationship', async ({
  page, apiAs, api, ts, cleanup,
}) => {
  blockedBy('Bug 4 (saving an object is black-holed when the user can see no sharing group: the empty Sharing group field breaks the form token)');
  const info = `QA wf object ${ts}`;
  const event = await apiAs('userA').createEvent({
    info,
    attributes: [{ type: 'ip-dst', category: 'Network activity', value: '203.0.113.60' }],
  });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  await page.getByRole('link', { name: 'Add Object' }).click();
  await expectScreen(dialog(page), 'add-object-template-step.png');
  await pick(dialog(page).getByRole('combobox', { name: /Template/ }), 'domain-ip', 'Domain-ip');
  await dialog(page).getByRole('button', { name: 'Next' }).click();

  const form = dialog(page);
  await form.getByRole('button', { name: /^Domain domain/ }).click();
  await form.getByRole('button', { name: /^Ip ip-dst/ }).click();
  const domainRow = form.locator('.attribute_row[data-object-relation="domain"]');
  const ipRow = form.locator('.attribute_row[data-object-relation="ip"]');
  await domainRow.locator('textarea.Attribute_value').fill('qa-wf-object.example');
  await ipRow.locator('textarea.Attribute_value').fill('203.0.113.61');
  await ipRow.getByText('IDS', { exact: true }).click();
  await ipRow.getByText('Correlate', { exact: true }).click();
  await form.getByRole('button', { name: 'Review', exact: true }).filter({ visible: true }).first().click();
  await form.getByRole('button', { name: 'Add Object' }).click();
  await expectDialogSaved(page);

  const objects = await openTab(page, 'Objects');
  await expect(objects.getByText('qa-wf-object.example').first()).toBeVisible();
  await expect(objects.getByText('203.0.113.61').first()).toBeVisible();

  // Relationship from 203.0.113.61 to the event attribute 203.0.113.60
  await row(objects, '203.0.113.61').getByRole('button').last().click();
  await page.getByRole('menuitem', { name: 'Add relationship' }).click();
  const rel = dialog(page);
  await rel.getByRole('textbox', { name: /Relationship type/ }).fill('related-to');
  await pick(rel.getByRole('combobox', { name: /Related/ }), '203.0.113.60');
  await rel.getByRole('button', { name: /Save|Add/ }).click();

  const saved = await apiAs('userA').getEvent(event.id);
  const attrs = saved.Object[0].Attribute;
  const ip = attrs.find((a) => a.value === '203.0.113.61');
  const domain = attrs.find((a) => a.value === 'qa-wf-object.example');
  expect(ip.to_ids).toBe(false);
  expect(ip.disable_correlation).toBe(true);
  expect(domain.to_ids).toBe(true);
  expect(domain.disable_correlation).toBe(false);
  await openTab(page, 'Objects');
  await expect(page.getByRole('tabpanel').filter({ visible: true }).getByText('related-to').first()).toBeVisible();
  await expectScreen(page.getByRole('tabpanel').filter({ visible: true }), 'wf-object-add.png');
});

test('Add attribute', async ({ page, apiAs, api, ts, cleanup }) => {
  const info = `QA wf attribute ${ts}`;
  const event = await apiAs('userA').createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  await page.getByRole('link', { name: 'Add Attribute' }).click();
  const form = dialog(page);
  await expectScreen(form, 'add-attribute-form.png');
  await pick(form.locator('#AttributeCategory + .ts-wrapper').getByRole('combobox'), 'Network activity');
  await pick(form.locator('#AttributeType + .ts-wrapper').getByRole('combobox'), 'domain');
  await form.getByRole('textbox', { name: /Enter the indicator value/ }).fill('qa-wf-attribute.example');
  await form.getByRole('checkbox', { name: /^For IDS/ }).check();
  await form.getByRole('button', { name: 'Add Attribute' }).click();

  await expect(page).toHaveURL(/\/events\/view2\/\d+/);
  const attributes = await openTab(page, 'Attributes');
  const r = row(attributes, 'qa-wf-attribute.example');
  await expect(r).toBeVisible();
  await expect(r.getByRole('cell', { name: 'domain', exact: true })).toBeVisible();
  await expect(r.getByRole('button', { name: /^IDS active/ })).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(r, 'wf-attribute-add.png');
});

test('Add tag and galaxy cluster on the event', async ({ page, apiAs, api, ts, cleanup }) => {
  const info = `QA wf event tags ${ts}`;
  const event = await apiAs('userA').createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  await expectScreen(dialog(page), 'edit-tags-dialog.png');
  await pick(dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first(), 'tlp:green');
  await dialog(page).getByRole('button', { name: 'Save Tags' }).click();
  await expect(page.getByText('Tags updated.')).toBeVisible();

  await page.getByRole('button', { name: 'Edit Galaxy Clusters' }).click();
  await pick(
    dialog(page).getByRole('combobox', { name: 'Search clusters to add…' }).first(),
    'Phishing - T1566',
    /^Phishing - T1566 /,
  );
  await dialog(page).getByRole('button', { name: /^Save/ }).click();

  const main = page.getByRole('main');
  await expect(main.getByText('tlp:green').first()).toBeVisible();
  await expect(main.getByText('Phishing - T1566').first()).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(eventCard(page, 'tags'), 'wf-event-tags.png');
    await expectScreen(eventCard(page, 'galaxy'), 'wf-event-galaxy.png');
});

test('Add tag and galaxy cluster on an attribute', async ({ page, apiAs, api, ts, cleanup }) => {
  const info = `QA wf attribute tags ${ts}`;
  const event = await apiAs('userA').createEvent({
    info,
    attributes: [{ type: 'ip-dst', category: 'Network activity', value: '203.0.113.62' }],
  });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  let attributes = await openTab(page, 'Attributes');
  await row(attributes, '203.0.113.62').getByRole('button', { name: 'Add a tag' }).click();
  await pick(dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first(), 'tlp:amber');
  await dialog(page).getByRole('button', { name: 'Save Tags' }).click();

  attributes = page.getByRole('tabpanel').filter({ visible: true });
  await row(attributes, '203.0.113.62').getByRole('button', { name: 'Add a galaxy cluster' }).click();
  await pick(
    dialog(page).getByRole('combobox', { name: 'Search clusters to add…' }).first(),
    'Phishing - T1566',
    /^Phishing - T1566 /,
  );
  await dialog(page).getByRole('button', { name: /^Save/ }).click();

  const r = row(page.getByRole('tabpanel').filter({ visible: true }), '203.0.113.62');
  await expect(r.getByText('tlp:amber')).toBeVisible();
  await expect(r.getByText('Phishing - T1566')).toBeVisible();
  const saved = await apiAs('userA').getEvent(event.id);
  expect((saved.Tag || []).map((t) => t.name)).not.toContain('tlp:amber');
  await expectNoErrorPage(page);
  await expectScreen(r, 'wf-attribute-tag-cluster.png');
});

test('Edit event distribution', async ({ page, apiAs, api, ts, cleanup }) => {
  const info = `QA wf distribution ${ts}`;
  const event = await apiAs('userA').createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  await page.getByRole('link', { name: 'Edit Event' }).click();
  await dialog(page).getByRole('radio', { name: /^All communities/ }).check();
  await dialog(page).getByRole('button', { name: 'Save Changes' }).click();

  await expect(page).toHaveURL(/\/events\/view2\/\d+/);
  await expect(page.getByRole('main').getByText('All communities', { exact: true })).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(eventSummary(page), 'wf-event-distribution.png');
});

test('Edit object comment', async ({ page, apiAs, api, ts, cleanup }) => {
  blockedBy('Bug 4 (saving an object is black-holed when the user can see no sharing group: the empty Sharing group field breaks the form token)');
  const info = `QA wf object comment ${ts}`;
  const comment = `QA comment ${ts}`;
  const event = await apiAs('userA').createEvent({
    info,
    objects: [{
      name: 'domain-ip',
      attributes: [{ object_relation: 'domain', type: 'domain', value: 'qa-wf-comment.example' }],
    }],
  });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  const objects = await openTab(page, 'Objects');
  await objects.getByRole('button', { name: /^domain-ip/ }).click();
  await objects.getByRole('link', { name: 'Edit', exact: true }).first().click();
  const form = dialog(page);
  await form.getByRole('textbox', { name: 'Comment', exact: true }).fill(comment);
  await form.getByRole('button', { name: 'Review', exact: true }).filter({ visible: true }).first().click();
  await form.getByRole('button', { name: 'Save Changes' }).click();
  await expectDialogSaved(page);

  await expect(page.getByText('Object saved.')).toBeVisible();
  await expect(page.getByRole('main').getByText(comment).first()).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(page.getByRole('tabpanel').filter({ visible: true }), 'wf-object-comment.png');
});

test('Edit attribute IDS state', async ({ page, apiAs, api, ts, cleanup }) => {
  const info = `QA wf ids ${ts}`;
  const event = await apiAs('userA').createEvent({
    info,
    attributes: [{ type: 'ip-dst', category: 'Network activity', value: '203.0.113.63', to_ids: true }],
  });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  const attributes = await openTab(page, 'Attributes');
  await rowAction(row(attributes, '203.0.113.63'), 'Edit');
  await dialog(page).getByRole('checkbox', { name: /^For IDS/ }).uncheck();
  await dialog(page).getByRole('button', { name: 'Save Changes' }).click();

  const r = row(page.getByRole('tabpanel').filter({ visible: true }), '203.0.113.63');
  await expect(r.getByRole('button', { name: /^IDS inactive/ })).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(r, 'wf-attribute-ids.png');
});

test('Add event report', async ({ page, apiAs, api, ts, cleanup }) => {
  blockedBy('Bug 10 (after saving, the old event page /events/view/<id> opens)');
  const info = `QA wf report ${ts}`;
  const name = `QA report ${ts}`;
  const event = await apiAs('userA').createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  await page.getByRole('link', { name: 'Add Event Report' }).click();
  const form = dialog(page);
  await form.getByRole('textbox', { name: /descriptive name/ }).fill(name);
  await form.getByRole('textbox', { name: /report content in Markdown/ }).fill('# Summary\n- First finding');
  await form.getByRole('button', { name: 'Add Report' }).click();

  await expect.soft(page).toHaveURL(/\/events\/view2\/\d+/);
  await openEvent(page, event.id);
  const reports = await openTab(page, 'Reports');
  const report = row(reports, name);
  await expect(report).toBeVisible();
  await report.getByRole('link', { name: /^#\d+$/ }).first().click();
  await expect(page.getByRole('heading', { name: 'Summary' })).toBeVisible();
  await expect(page.getByRole('listitem').filter({ hasText: 'First finding' })).toBeVisible();
  const rendered = page.locator('.card').filter({ has: page.getByRole('heading', { name: 'Summary' }) });
  await expectScreen(rendered.last(), 'event-report-view.png');
  await expectNoErrorPage(page);
});

test('Add a small attachment', async ({ page, apiAs, api, ts, cleanup }, testInfo) => {
  const info = `QA wf attachment ${ts}`;
  const event = await apiAs('userA').createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  await page.getByRole('link', { name: 'Add Attachment' }).click();
  const form = dialog(page);
  await form.locator('input[type=file]').setInputFiles({
    name: 'qa-note.txt', mimeType: 'text/plain', buffer: Buffer.from(`QA attachment ${ts}`),
  });
  await form.getByRole('checkbox', { name: /^Malware Sample/ }).uncheck();
  await form.getByRole('button', { name: 'Upload' }).click();

  const attributes = await openTab(page, 'Attributes');
  const r = row(attributes, 'qa-note.txt');
  await expect(r).toBeVisible();
  await expect(r.getByRole('cell', { name: 'attachment', exact: true })).toBeVisible();

  // Downloads are in the "Event Attachments" panel of the General tab.
  const general = await openTab(page, 'General');
  const download = page.waitForEvent('download');
  await row(general, 'qa-note.txt').getByRole('link', { name: 'Download' }).click();
  const file = testInfo.outputPath('qa-note.txt');
  await (await download).saveAs(file);
  expect(require('fs').readFileSync(file, 'utf8')).toBe(`QA attachment ${ts}`);
  await expectNoErrorPage(page);
  await openEvent(page, event.id);
    await expectScreen(eventCard(page, 'attachment'), 'wf-attachment.png');
});

test('Populate from MISP JSON', async ({ page, apiAs, api, ts, cleanup }) => {
  const info = `QA wf json ${ts}`;
  const event = await apiAs('userA').createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  await page.getByRole('link', { name: 'Populate from' }).click();
  const form = dialog(page);
  await expectScreen(form, 'populate-from-dialog.png');
  await form.getByRole('button', { name: /^MISP JSON/ }).click();
  await form.getByRole('textbox', { name: 'MISP Event JSON' }).fill(JSON.stringify({
    Event: { Attribute: [{ type: 'domain', category: 'Network activity', value: 'qa-wf-json.example', to_ids: true }] },
  }));
  await form.getByRole('button', { name: 'Populate from JSON' }).click();

  await openEvent(page, event.id);
  const r = row(await openTab(page, 'Attributes'), 'qa-wf-json.example');
  await expect(r.getByRole('cell', { name: 'domain', exact: true })).toBeVisible();
  await expect(r.getByRole('button', { name: /^IDS active/ })).toBeVisible();
  expect(await api.findEvents(info)).toHaveLength(1);
  await expectNoErrorPage(page);
  await expectScreen(r, 'wf-populate-json.png');
});

test('Populate from freetext import', async ({ page, apiAs, api, ts, cleanup }) => {
  const info = `QA wf freetext ${ts}`;
  const event = await apiAs('userA').createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  const results = await freetextImport(
    page, 'Seen: hxxp://qa-wf-freetext[.]example/login and 203.0.113[.]64',
  );
  expect(await freetextResults(results)).toEqual([
    ['http://qa-wf-freetext.example/login', 'url'],
    ['203.0.113.64', 'ip-dst'],
  ]);
  await expectScreen(results, 'freetext-review.png');
  await results.getByRole('button', { name: 'Create attributes' }).click();
  await expect(dialog(page)).toHaveCount(0);

  const attributes = await openTab(page, 'Attributes');
  await expect(row(attributes, 'http://qa-wf-freetext.example/login')).toBeVisible();
  await expect(row(attributes, '203.0.113.64')).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(attributes.getByRole('table'), 'wf-populate-freetext.png');
});

test('Enrich event', async ({ page, apiAs, api, ts, cleanup }) => {
  const info = `QA wf enrich ${ts}`;
  const event = await apiAs('userA').createEvent({
    info,
    attributes: [{ type: 'domain', category: 'Network activity', value: 'qa-wf-enrich.example' }],
  });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  await page.getByRole('link', { name: 'Enrich Event' }).click();
  const form = dialog(page);
  await expect(form.getByRole('heading', { name: 'Enrich event' })).toBeVisible();
  test.skip(
    await form.getByText('No expansion module is enabled').isVisible(),
    'Test data (before): at least one enrichment module must be enabled on the instance',
  );
  await form.getByRole('checkbox').first().check();
  await form.getByRole('button', { name: /Enrich|Run|Submit/ }).click();
  await expect(page.getByText(/Enrichment runs as a background job|Enrichment results/)).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(page.getByRole('main'), 'wf-enrich.png');
});

test.describe('with the publish permission', () => {
  test.use({ role: 'orgAdminA' });

  test('Publish event', async ({ page, apiAs, api, ts, cleanup }) => {
    const info = `QA wf publish ${ts}`;
    const event = await apiAs('orgAdminA').createEvent({
      info,
      attributes: [{ type: 'ip-dst', category: 'Network activity', value: '203.0.113.65' }],
    });
    cleanup(() => api.deleteEventsByInfo(info));

    await openEvent(page, event.id);
    await page.getByRole('link', { name: 'Publish Event' }).click();
    const confirm = dialog(page);
    await expect(confirm.getByRole('switch', { name: 'Send notification email' })).not.toBeChecked();
    await expectScreen(confirm, 'publish-dialog.png');
    await confirm.getByRole('button', { name: 'Publish', exact: true }).click();

    await expect(page).toHaveURL(/\/events\/view2\/\d+/);
    await expect(page.getByText('Job queued')).toBeVisible();
    await expectAfterReload(page, () => expect(page.getByRole('main')).toContainText(/Publication\s*Published/));
    await expectNoErrorPage(page);
    await expectScreen(eventSummary(page), 'wf-publish.png');
  });
});

test('Batch import of attributes', async ({ page, apiAs, api, ts, cleanup }) => {
  const info = `QA wf batch ${ts}`;
  const values = ['203.0.113.70', '203.0.113.71', '203.0.113.72'];
  const event = await apiAs('userA').createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  await page.getByRole('link', { name: 'Add Attribute' }).click();
  const form = dialog(page);
  await form.getByRole('checkbox', { name: /^Batch Import/ }).check();
  await pick(form.locator('#AttributeCategory + .ts-wrapper').getByRole('combobox'), 'Network activity');
  await pick(form.locator('#AttributeType + .ts-wrapper').getByRole('combobox'), 'ip-dst');
  await form.getByRole('textbox', { name: /Enter the indicator value/ }).fill(`${values.join('\n')}\n`);
  await form.getByRole('button', { name: 'Add Attribute' }).click();

  const attributes = await openTab(page, 'Attributes');
  for (const v of values) {
    await expect(row(attributes, v).getByRole('cell', { name: 'ip-dst', exact: true })).toBeVisible();
  }
  expect((await apiAs('userA').getEvent(event.id)).Attribute).toHaveLength(3);
  await expectNoErrorPage(page);
  await expectScreen(attributes.getByRole('table'), 'wf-batch-import.png');
});

test('Delete and restore an attribute', async ({ page, apiAs, api, ts, cleanup }) => {
  const info = `QA wf restore ${ts}`;
  const event = await apiAs('userA').createEvent({
    info,
    attributes: ['203.0.113.73', '203.0.113.74']
      .map((value) => ({ type: 'ip-dst', category: 'Network activity', value })),
  });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  let attributes = await openTab(page, 'Attributes');
  await rowAction(row(attributes, '203.0.113.73'), 'Delete');
  await dialog(page).getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(row(attributes, '203.0.113.73')).toHaveCount(0);
  await expect(row(attributes, '203.0.113.74')).toBeVisible();

  await attributes.getByRole('link', { name: /^Deleted/ }).click();
  attributes = page.getByRole('tabpanel').filter({ visible: true });
  await expect(row(attributes, '203.0.113.73')).toBeVisible();
  await rowAction(row(attributes, '203.0.113.73'), 'Restore');
  await dialog(page).getByRole('button', { name: 'Restore', exact: true }).click();
  await attributes.getByRole('link', { name: /^Deleted/ }).click();

  attributes = page.getByRole('tabpanel').filter({ visible: true });
  await expect(row(attributes, '203.0.113.73')).toBeVisible();
  await expect(row(attributes, '203.0.113.74')).toBeVisible();
  const saved = await apiAs('userA').getEvent(event.id);
  expect(saved.Attribute.find((a) => a.value === '203.0.113.73').deleted).toBe(false);
  await expectNoErrorPage(page);
  await expectScreen(attributes.getByRole('table'), 'wf-delete-restore.png');
});
