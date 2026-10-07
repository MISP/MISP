// ../../event-report/extract/extract.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, openEvent, openTab,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const main = (page) => page.getByRole('main');
const NO_EXTRACTION = 'Missing feature: Overmind only offers the AI extraction ("Extract indicators"), '
  + 'not the extraction of all entities of the report';

async function reportWithIndicators(api, cleanup, ts) {
  const event = await api.createEvent({ info: `QA event reports ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));
  const report = await api.createReport(event.id, `QA extract ${ts}`,
    '# QA XSS report\n\nSeen 198.51.100.151, qa-report.example and 44d88612fea8a8f36de82e1278abb02f.');
  return { event, report };
}

async function openExtraction(page, report) {
  await page.goto(`/event_reports/view/${report.id}`);
  await page.getByRole('tab', { name: 'Edit Content' }).click();
  await page.getByRole('button', { name: 'Menu' }).click();
  const extract = page.getByRole('link', { name: /Extract (all|entities)/i })
    .or(page.getByRole('button', { name: /Extract (all|entities)/i }));
  await expect(extract.first(), 'an extraction of all entities').toBeVisible({ timeout: 5_000 });
  await extract.first().click();
}

test('Report – extract indicators', async ({ page, api, ts, cleanup }) => {
  blockedBy(NO_EXTRACTION);
  const { event, report } = await reportWithIndicators(api, cleanup, ts);
  await openExtraction(page, report);

  await expect.poll(async () => (await api.getEvent(event.id)).Attribute.map((a) => a.value).sort())
    .toEqual(['198.51.100.151', '44d88612fea8a8f36de82e1278abb02f', 'qa-report.example']);
});

test('Report – replacements are reviewed', async ({ page, api, ts, cleanup }) => {
  blockedBy(NO_EXTRACTION);
  const { report } = await reportWithIndicators(api, cleanup, ts);
  await openExtraction(page, report);

  await expect(page.getByRole('dialog').getByText(/replace/i).first()).toBeVisible();
  expect((await api.get(`/eventReports/view/${report.id}`)).EventReport.content).toContain('# QA XSS report');
});

test('Report – import from URL disabled', async ({ page, api, ts, cleanup }) => {
  const event = await api.createEvent({ info: `QA event reports ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  const reports = await openTab(page, 'Reports');
  const importUrl = page.getByRole('link', { name: /import.*url/i }).or(page.getByRole('button', { name: /import.*url/i }));

  // Not offered, or refused with the message about the setting.
  if (await importUrl.count()) {
    await importUrl.first().click();
    await page.getByRole('dialog').getByRole('textbox').first().fill('https://qa-report.example/page');
    await page.getByRole('dialog').getByRole('button', { name: /Import|Submit/ }).click();
    await expect(page.getByText(/Security\.eventreport_enable_arbitrary_urls/).first()).toBeVisible();
  }
  await expectNoErrorPage(page);
  await expectScreen(reports, 'report-import-url-off.png');
});

test('Report – download as PDF', async ({ page, api, ts, cleanup }, testInfo) => {
  const event = await api.createEvent({ info: `QA event reports ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));
  const report = await api.createReport(event.id, `QA markdown ${ts}`, '# QA title\n\n- item');

  await page.goto(`/event_reports/view/${report.id}`);
  await page.getByRole('tab', { name: 'Edit Content' }).click();
  await page.getByRole('button', { name: 'Menu' }).click();
  const viaModule = page.getByRole('link', { name: /Download PDF \(via misp-module\)/ });
  test.skip(await viaModule.evaluate((a) => a.classList.contains('disabled')),
    'Test data (before): the misp-module convert_markdown_to_pdf must be enabled on the instance');

  const pending = page.waitForEvent('download');
  await viaModule.click();
  const file = testInfo.outputPath('report.pdf');
  await (await pending).saveAs(file);
  expect(require('fs').readFileSync(file).subarray(0, 4).toString()).toBe('%PDF');
  await expectNoErrorPage(page);
});

test('Report – old rendered view', async ({ page, api, ts, cleanup }) => {
  blockedBy('New bug: /eventReports/viewRendered/<id> gives "An Internal Error Has Occurred." '
    + '(MissingViewException: EventReports/view_rendered.ctp is missing)');
  const event = await api.createEvent({ info: `QA event reports ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));
  const report = await api.createReport(event.id, `QA rendered ${ts}`, '# QA');

  const response = await page.goto(`/eventReports/viewRendered/${report.id}`);
  await expectNoErrorPage(page);
  expect(response.status(), 'shown (200) or not found (404), never 500').not.toBe(500);
  await expectScreen(main(page), 'report-view-rendered.png', { hide: [ts] });
});
