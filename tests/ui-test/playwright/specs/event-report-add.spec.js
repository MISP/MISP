// ../../event-report/add/add.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, openEvent, openTab, row, rowAction, dialog,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const main = (page) => page.getByRole('main');
// Markdown shows the quotes as typographic ones: alert(‘qa-script’).
const SCRIPT_TEXT = /<script>alert\(.qa-script.\)<\/script>/;
const XSS = [
  '# QA XSS report',
  "<script>alert('qa-script')</script>",
  '<img src=x onerror="alert(\'qa-img\')">',
  "[click me](javascript:alert('qa-link'))",
  "![img](javascript:alert('qa-image'))",
].join('\n\n');

async function eventWithReports(api, cleanup, ts, attributes = []) {
  const event = await api.createEvent({ info: `QA event reports ${ts}`, attributes });
  cleanup(() => api.deleteEventsByInfo(event.info));
  return event;
}

// Add Event Report from the event page; returns once the window is closed.
async function addReport(page, eventId, name, content) {
  await openEvent(page, eventId);
  await page.getByRole('link', { name: 'Add Event Report' }).click();
  const form = dialog(page);
  await form.getByRole('textbox', { name: /descriptive name/ }).fill(name);
  await form.getByRole('textbox', { name: /report content in Markdown/ }).fill(content);
  await form.getByRole('button', { name: 'Add Report' }).click();
  await expect(form).toBeHidden();
}

test('Report – Markdown', async ({ page, api, ts, cleanup }) => {
  const event = await eventWithReports(api, cleanup, ts);
  await addReport(page, event.id, `QA markdown ${ts}`,
    '# QA title\n\n- first item\n- second item\n\n| Name | Value |\n| --- | --- |\n| ip | 198.51.100.1 |');

  const report = (await api.getEvent(event.id)).EventReport[0];
  await page.goto(`/event_reports/view/${report.id}`);
  await expect(main(page).getByRole('heading', { name: 'QA title' })).toBeVisible();
  await expect(main(page).getByRole('listitem').filter({ hasText: 'second item' })).toBeVisible();
  const table = main(page).getByRole('table').filter({ hasText: '198.51.100.1' });
  await expect(table.getByRole('cell', { name: '198.51.100.1' })).toBeVisible();
  await expect(main(page).getByText('| Name | Value |').filter({ visible: true })).toHaveCount(0);
  await expectScreen(table, 'report-markdown-table.png');
});

test('Report – HTML and scripts', async ({ page, api, ts, cleanup }) => {
  const event = await eventWithReports(api, cleanup, ts);
  const report = await api.createReport(event.id, `<b>QA report</b> 🚀 ${ts}`, XSS);
  const alerts = [];
  page.on('dialog', (d) => { alerts.push(d.message()); d.dismiss(); });

  await page.goto(`/event_reports/view/${report.id}`);
  // The raw Markdown is also in the hidden editor: look at the rendered text only.
  const shown = (text) => main(page).getByText(text).filter({ visible: true }).first();
  await expect(shown(SCRIPT_TEXT)).toBeVisible();
  await expect(shown(/<img src=x onerror=/)).toBeVisible();
  const link = main(page).getByRole('link', { name: 'click me' });
  if (await link.count()) await link.click();
  else await shown(/click me/).click();
  await page.waitForTimeout(500);

  expect(alerts, 'no alert pops up').toEqual([]);
  await expect(page).toHaveURL(new RegExp(`/event_reports/view/${report.id}`));
  await expectScreen(shown(SCRIPT_TEXT), 'report-xss.png');
});

test('Report – name with HTML and emoji', async ({ page, api, ts, cleanup }) => {
  const event = await eventWithReports(api, cleanup, ts);
  const name = `<b>QA report</b> 🚀 ${ts}`;
  const report = await api.createReport(event.id, name, 'QA');

  await openEvent(page, event.id);
  const reports = await openTab(page, 'Reports');
  await expect(row(reports, name)).toBeVisible();
  await expect(reports.locator('b', { hasText: /^QA report$/ })).toHaveCount(0);
  await page.goto(`/event_reports/view/${report.id}`);
  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible();
  await expectScreen(page.getByRole('heading', { name, level: 1 }), 'report-name.png');
});

test('Report – very large content', async ({ page, api, ts, cleanup }) => {
  test.setTimeout(180_000);
  const event = await eventWithReports(api, cleanup, ts);
  const big = `# QA big report\n\n${'QA line of text for a big report.\n'.repeat(95_000)}QA last word`;
  const report = await api.createReport(event.id, `QA big report ${ts}`, big);

  const start = Date.now();
  await page.goto(`/event_reports/view/${report.id}`);
  await expect(main(page).getByText('QA last word').filter({ visible: true }).first()).toBeVisible({ timeout: 60_000 });
  test.info().annotations.push({ type: 'report shown after', description: `${Date.now() - start} ms` });

  await page.getByRole('tab', { name: 'Edit Content' }).click();
  const editor = page.getByRole('tabpanel').filter({ visible: true }).locator('textarea').first();
  await editor.evaluate((t) => {
    t.value = t.value.replace('QA last word', 'QA edited word');
    t.dispatchEvent(new Event('input', { bubbles: true }));
  });
  const saved = Date.now();
  await page.getByRole('button', { name: 'Save' }).click();
  await expect.poll(async () => (await api.get(`/eventReports/view/${report.id}`)).EventReport.content
    .endsWith('QA edited word'), { timeout: 30_000 }).toBe(true);
  expect(Date.now() - saved, 'saved in a few seconds').toBeLessThan(15_000);
  await expectNoErrorPage(page);
  await expectScreen(page.getByRole('heading', { level: 1 }).first(), 'report-large.png', { hide: [ts] });
});

test('Report – reference to an attribute', async ({ page, api, ts, cleanup }) => {
  const event = await eventWithReports(api, cleanup, ts,
    [{ type: 'ip-dst', category: 'Network activity', value: '198.51.100.150' }]);
  const attribute = (await api.getEvent(event.id)).Attribute[0];
  const report = await api.createReport(event.id, `QA reference ${ts}`, `Reference: @[attribute](${attribute.uuid})`);

  await page.goto(`/event_reports/view/${report.id}`);
  const reference = main(page).getByText('198.51.100.150').filter({ visible: true }).first();
  await expect(reference).toBeVisible();
  await expectScreen(reference.locator('xpath=..'), 'report-reference.png');
  // A click opens the details of the attribute.
  await reference.click();
  const details = page.locator('.popover.show').first();
  await expect(details).toContainText(new RegExp(`Attribute\\s*ID\\s*${attribute.id}`));
  await expect(details).toContainText('ip-dst');
});

test('Report – delete and restore', async ({ page, api, ts, cleanup }) => {
  blockedBy('Missing feature: deleted reports cannot be shown, so not restored – no Deleted filter in '
    + 'the Reports tab or in /event_reports/index');
  const event = await eventWithReports(api, cleanup, ts);
  const name = `QA to delete ${ts}`;
  await addReport(page, event.id, name, 'QA');
  const report = (await api.getEvent(event.id)).EventReport[0];

  await page.goto(`/event_reports/view/${report.id}`);
  await page.getByRole('link', { name: 'Delete Report' }).click();
  await dialog(page).getByRole('button', { name: /Delete/ }).last().click();
  // A deleted report is not served any more (404) until it is restored.
  await expect.poll(async () => api.get(`/eventReports/view/${report.id}`).then(() => 'active', () => 'deleted'))
    .toBe('deleted');

  await openEvent(page, event.id);
  const reports = await openTab(page, 'Reports');
  const showDeleted = reports.getByRole('link', { name: /^Deleted/ });
  await expect(showDeleted, 'a way to show the deleted reports').toBeVisible({ timeout: 5_000 });
  await showDeleted.click();
  const deleted = page.getByRole('tabpanel').filter({ visible: true });
  await rowAction(row(deleted, name), 'Restore');
  await dialog(page).getByRole('button', { name: /Restore/ }).click();

  await expect.poll(async () => api.get(`/eventReports/view/${report.id}`).then(() => 'active', () => 'deleted'))
    .toBe('active');
  await page.goto(`/event_reports/view/${report.id}`);
  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible();
  await expectScreen(page.getByRole('heading', { name, level: 1 }), 'report-delete-restore.png', { hide: [ts] });
});

test('Report – page shown after creating', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 10 (creating an event report opens the old event page /events/view/<id>)');
  const event = await api.createEvent({ info: `QA report redirect ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  await page.getByRole('link', { name: 'Add Event Report' }).click();
  await dialog(page).getByRole('textbox', { name: /descriptive name/ }).fill(`QA report ${ts}`);
  await dialog(page).getByRole('textbox', { name: /report content in Markdown/ }).fill('QA text');
  await dialog(page).getByRole('button', { name: 'Add Report' }).click();

  await expect(page).toHaveURL(new RegExp(`/events/view2/${event.id}`));
  const reports = page.getByRole('tabpanel').filter({ visible: true });
  await expect(row(reports, `QA report ${ts}`)).toBeVisible();
  await expectScreen(row(reports, `QA report ${ts}`), 'report-add-redirect.png', { hide: [ts] });
});
