// ../../../use-case/06-defence-export.md
const fs = require('fs');
const { test, expect, knownBug, openEvent, dialog } = require('../../helpers');

test.use({ role: 'siteAdmin' });

// Clicks one export of the "Download as" window and returns the file content.
async function exportAs(page, name, testInfo) {
  await page.getByRole('link', { name: 'Download as' }).click();
  const box = dialog(page);
  const link = box.getByRole('link', { name });
  await expect(box.getByRole('checkbox', { name: 'Include non-IDS marked attributes' }).first())
    .not.toBeChecked();
  const download = page.waitForEvent('download');
  await link.click();
  const file = testInfo.outputPath((await download).suggestedFilename());
  await (await download).saveAs(file);
  await box.getByRole('button', { name: 'Close' }).click();
  return fs.readFileSync(file, 'utf8');
}

test('Use case 6 – Feed the defence tools', async ({ page, api, ts, cleanup }, testInfo) => {
  knownBug('Bug 2 (CSV does not neutralise formulas; not triggered by this data)');
  const info = `Fake-Parcel export ${ts}`;
  const event = await api.createEvent({
    info,
    publish: true,
    attributes: [
      { type: 'domain', category: 'Network activity', value: 'parcel-tracking.example', to_ids: true },
      { type: 'ip-dst', category: 'Network activity', value: '203.0.113.45', to_ids: true },
      { type: 'ip-dst', category: 'Network activity', value: '8.8.8.8', to_ids: false },
    ],
  });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  const text = await test.step('Phase 1 – Export as text for a firewall',
    () => exportAs(page, 'Export all attribute values as a text file', testInfo));
  const csv = await test.step('Phase 2 – Export as CSV for a SIEM',
    () => exportAs(page, /^CSV \(NOT FOR EXCEL/, testInfo));

  expect(text.trim().split(/\r?\n/).sort()).toEqual(['203.0.113.45', 'parcel-tracking.example']);
  expect(csv).toContain('parcel-tracking.example');
  expect(csv).toContain('203.0.113.45');
  expect(csv).not.toContain('8.8.8.8');
});
