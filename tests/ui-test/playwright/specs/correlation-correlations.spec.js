// ../../correlation/correlations/correlations.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen,
  openEvent, openTab, row, dialog, expectAfterReload, uniqueIp,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function correlatedEvents(api, cleanup, ts, value, count = 2) {
  const events = [];
  for (let i = 0; i < count; i += 1) {
    const info = `QA correlation ${String.fromCharCode(65 + i)} ${ts}`;
    cleanup(() => api.deleteEventsByInfo(info));
    events.push(await api.createEvent({
      info, attributes: [{ type: 'ip-dst', category: 'Network activity', value }],
    }));
  }
  return events;
}

function relatedLink(tab, info) {
  return tab.getByRole('link', { name: new RegExp(`^${info}`) });
}

async function openExclusionForm(page) {
  await page.goto('/correlation_exclusions/index');
  await page.getByRole('link', { name: 'Add correlation exclusion entry' }).click();
  const form = dialog(page);
  await expect(form.getByRole('heading', { name: 'Add Exclusion' })).toBeVisible();
  return form;
}

test('Correlation – same value in two events', async ({ page, api, ts, cleanup }) => {
  const value = uniqueIp(ts);
  const [a, b] = await correlatedEvents(api, cleanup, ts, value);

  await openEvent(page, a.id);
  await expect(relatedLink(await openTab(page, 'Correlation'), b.info)).toBeVisible();
  const attributes = await openTab(page, 'Attributes');
  await expect(row(attributes, value).getByRole('link', { name: `#${b.id}`, exact: true })).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(row(attributes, value), 'correlation-two-events.png');
});

test('Correlation exclusion – existing correlations', async ({ page, api, ts, cleanup }) => {
  const value = uniqueIp(ts);
  const [a, b] = await correlatedEvents(api, cleanup, ts, value);
  cleanup(() => api.deleteCorrelationExclusion(value));
  const related = async () => ((await api.getEvent(a.id)).RelatedEvent || [])
    .map((r) => (r.Event || r).info);

  const form = await openExclusionForm(page);
  await form.getByRole('textbox', { name: '8.8.8.8' }).fill(value);
  await form.getByRole('textbox', { name: /Why this value/ }).fill('QA exclusion');
  await form.getByRole('button', { name: 'Add Exclusion' }).click();
  await expect(row(page.getByRole('main'), value)).toBeVisible();

  // The page hides correlations on excluded values at once; the stored
  // correlation stays until the clean up, as the API shows.
  await openEvent(page, a.id);
  await expect(relatedLink(await openTab(page, 'Correlation'), b.info)).toHaveCount(0);
  expect(await related()).toContain(b.info);

  await page.goto('/correlation_exclusions/index');
  await page.getByRole('link', { name: 'Clean up correlations' }).click();
  await expect(page.getByText('Correlations cleanup initiated')).toBeVisible();
  await expect(async () => expect(await related()).not.toContain(b.info))
    .toPass({ timeout: 60_000, intervals: [2_000] });

  await openEvent(page, a.id);
  const attributes = await openTab(page, 'Attributes');
  await expect(row(attributes, value).getByRole('link', { name: `#${b.id}`, exact: true }))
    .toHaveCount(0);
  await expectNoErrorPage(page);
  await expectScreen(row(attributes, value), 'correlation-exclusion-cleanup.png');
});

test('Correlation exclusion – same value twice', async ({ page, api, ts, cleanup }) => {
  const value = uniqueIp(ts);
  cleanup(() => api.deleteCorrelationExclusion(value));
  await api.addCorrelationExclusion(value, 'QA exclusion');
  blockedBy('Bug 18 (a refused exclusion opens an unstyled page without the reason)');

  const form = await openExclusionForm(page);
  await form.getByRole('textbox', { name: '8.8.8.8' }).fill(value);
  await form.getByRole('button', { name: 'Add Exclusion' }).click();
  await expectNoErrorPage(page);
  await expect(page).toHaveURL(/\/correlation_exclusions\/index/);
  await expect(page.getByText('Value is already in the exclusion list.')).toBeVisible();
  expect((await api.correlationExclusions()).filter((e) => e.value === value)).toHaveLength(1);
  await expectScreen(form, 'correlation-exclusion-duplicate.png');
});

test('Correlation exclusion – empty value', async ({ page, api }) => {
  const before = (await api.correlationExclusions()).length;

  const form = await openExclusionForm(page);
  await form.getByRole('button', { name: 'Add Exclusion' }).click();
  await expect(form.getByText('Please provide a value to exclude.')).toBeVisible();
  await expect(form).toBeVisible();
  expect(await api.correlationExclusions()).toHaveLength(before);
  // Only the dialog: other exclusions on the page behind may quote error texts.
  await expect(form.getByText('An Internal Error Has Occurred.')).toHaveCount(0);
  await expectScreen(form, 'correlation-exclusion-empty.png');
});

test('Correlation – top correlations', async ({ page, api, ts, cleanup }) => {
  const value = uniqueIp(ts);
  // Four events make the value one of the most correlated of the instance.
  await correlatedEvents(api, cleanup, ts, value, 4);

  await page.goto('/correlations/top');
  await page.getByRole('link', { name: 'Regenerate cache' }).click();
  await expectNoErrorPage(page);
  const main = page.getByRole('main');
  await expectAfterReload(page, async () => {
    await expect(row(main, value)).toBeVisible();
  });
  const count = row(main, value).getByRole('cell').nth(3);
  expect(Number(await count.innerText())).toBeGreaterThan(0);
  await expectNoErrorPage(page);
  await expectScreen(row(main, value), 'correlation-top.png');
});
