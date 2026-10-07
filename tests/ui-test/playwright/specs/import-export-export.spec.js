// ../../import-export/export/export.md
const fs = require('fs');
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, openEvent, row, dialog, pick,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function csvEvent(api, cleanup, ts) {
  const event = await api.createEvent({
    info: `QA export csv formula ${ts}`,
    attributes: [
      { type: 'ip-dst', category: 'Network activity', value: '198.51.100.130', to_ids: true, comment: '=HYPERLINK("http://qa-csv.example","click")' },
      { type: 'ip-dst', category: 'Network activity', value: '198.51.100.131', to_ids: true, comment: '+cmd|calc' },
    ],
  });
  cleanup(() => api.deleteEventsByInfo(event.info));
  return event;
}

// Downloads one format of the "Download as" window and returns the file content.
async function downloadAs(page, eventId, name, testInfo) {
  await openEvent(page, eventId);
  await page.getByRole('link', { name: 'Download as' }).click();
  const pending = page.waitForEvent('download');
  await dialog(page).getByRole('link', { name }).click();
  const file = testInfo.outputPath((await pending).suggestedFilename());
  await (await pending).saveAs(file);
  return fs.readFileSync(file, 'utf8');
}

test('Export – MISP JSON', async ({ page, api, ts, cleanup }, testInfo) => {
  const event = await csvEvent(api, cleanup, ts);
  const text = await downloadAs(page, event.id, /^MISP JSON/, testInfo);

  // The download is a search result: {"response": [{"Event": …}]}.
  const [{ Event: exported }] = JSON.parse(text).response;
  expect(exported.uuid).toBe(event.uuid);
  expect(exported.Attribute.map((a) => a.value).sort()).toEqual(['198.51.100.130', '198.51.100.131']);
  await expectScreen(dialog(page), 'export-misp-json.png');
});

test('Export – CSV formulas', async ({ page, api, ts, cleanup }, testInfo) => {
  blockedBy('Bug 2 (the CSV export does not neutralise spreadsheet formulas)');
  const event = await csvEvent(api, cleanup, ts);
  const csv = await downloadAs(page, event.id, /^CSV \(NOT FOR EXCEL/, testInfo);

  expect(csv).not.toMatch(/(^|,|")=HYPERLINK/m);
  expect(csv).not.toMatch(/(^|,|")\+cmd\|calc/m);
});

test('Export – STIX 2', async ({ page, api, ts, cleanup }, testInfo) => {
  test.setTimeout(120_000);
  const event = await csvEvent(api, cleanup, ts);
  const text = await downloadAs(page, event.id, /^STIX 2$/, testInfo);

  const bundle = JSON.parse(text);
  expect(bundle.type).toBe('bundle');
  expect(JSON.stringify(bundle)).toContain('198.51.100.130');
  await expectNoErrorPage(page);
});

test('Export – several events', async ({ page, api, ts, cleanup }, testInfo) => {
  const names = [`QA export several 1 ${ts}`, `QA export several 2 ${ts}`];
  for (const info of names) {
    await api.createEvent({ info });
    cleanup(() => api.deleteEventsByInfo(info));
  }
  await page.goto('/events/index');
  for (const info of names) await row(page.getByRole('main'), info).getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Export' }).click();
  await pick(dialog(page).getByRole('combobox', { name: /Export Format/ }), 'MISP JSON');
  const pending = page.waitForEvent('download');
  await dialog(page).getByRole('button', { name: 'Export' }).click();
  const file = testInfo.outputPath('several.json');
  await (await pending).saveAs(file);

  const text = fs.readFileSync(file, 'utf8');
  for (const info of names) expect(text).toContain(info);
});

test('Export – cached exports', async ({ page }) => {
  test.setTimeout(240_000);
  await page.goto('/events/export');
  const csv = page.getByRole('main').getByRole('row').filter({ hasText: /^\s*CSV_All/ });
  await csv.getByRole('button', { name: 'Generate' }).click();

  // Up to date and downloadable, or the warning that the workers are down.
  const workersDown = page.getByText('Warning, the background worker is not responding!');
  await expect(async () => {
    await page.reload();
    const current = page.getByRole('main').getByRole('row').filter({ hasText: /^\s*CSV_All/ });
    expect((await workersDown.count()) > 0 || /Up to date/i.test(await current.innerText())).toBe(true);
  }).toPass({ timeout: 180_000, intervals: [5_000] });
  if (!(await workersDown.count())) {
    await expect(page.getByRole('main').getByRole('row').filter({ hasText: /^\s*CSV_All/ })
      .getByRole('link', { name: 'Download' })).toBeEnabled();
  }
  await expectNoErrorPage(page);
});
