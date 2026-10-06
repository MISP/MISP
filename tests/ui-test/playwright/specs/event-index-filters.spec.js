// ../../event/index/filters.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, pick, row,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const main = (page) => page.getByRole('main');
// One "#<id>" link per event row of the list.
const eventIds = (page) => main(page).getByRole('link', { name: /^#\d+$/ });

async function applyFilters(page, filters) {
  await page.goto('/events/index');
  await page.getByRole('button', { name: 'More filters' }).click();
  for (const [field, search, option] of filters) {
    await pick(page.locator(`select[name=${field}] + .ts-wrapper`).getByRole('combobox'), search, option);
  }
  await page.getByRole('button', { name: 'Apply filters' }).click();
}

test('Event index – filter by galaxy', async ({ page, api }) => {
  blockedBy('Bug 1 (the Galaxy filter of the Events list is ignored)');
  const galaxy = 'Ammunitions';
  const { response } = await api.post('/events/restSearch', {
    tags: ['misp-galaxy:ammunitions%'], metadata: true, returnFormat: 'json',
  });
  expect(response, `test data: no event uses the galaxy ${galaxy}`).toHaveLength(0);

  await applyFilters(page, [['galaxy', galaxy]]);

  await expect(page, 'the galaxy filter is sent').toHaveURL(/searchgalaxy:Ammunitions/i);
  await expectNoErrorPage(page);
  await expect(eventIds(page)).toHaveCount(0);
  await expectScreen(main(page), 'event-index-filter-galaxy.png');
});

test('Event index – filter by tag', async ({ page, api, ts, cleanup }) => {
  const tag = `qa:pw-unused-tag-${ts}`;
  await api.createTag(tag);
  cleanup(() => api.deleteTag(tag));

  await applyFilters(page, [['tag', tag]]);

  await expect(page).toHaveURL(/searchtag:/);
  await expectNoErrorPage(page);
  await expect(eventIds(page)).toHaveCount(0);
  await expectScreen(main(page), 'event-index-filter-tag.png');
});

test('Event index – date range reversed', async ({ page }) => {
  await page.goto('/events/index/searchDatefrom:2026-10-01/searchDateuntil:2026-01-01');

  await expectNoErrorPage(page);
  await expect(eventIds(page)).toHaveCount(0);
  await expectScreen(main(page), 'event-index-date-reversed.png');
});

test('Event index – search with special characters', async ({ page }) => {
  const text = '\'%"<b>🚀';
  await page.goto('/events/index');
  const search = page.getByRole('textbox', { name: 'Search by info, ID or UUID' });
  await search.fill(text);
  await search.press('Enter');

  await expectNoErrorPage(page);
  await expect(page.getByRole('textbox', { name: 'Search by info, ID or UUID' })).toHaveValue(text);
  await expect(page.locator('main b', { hasText: '🚀' })).toHaveCount(0);
  for (const info of await main(page).getByRole('row').allInnerTexts()) {
    if (/#\d+/.test(info)) expect(info).toContain(text);
  }
  await expectScreen(main(page), 'event-index-search-special.png');
});

test('Event index – page out of range', async ({ page }) => {
  await page.goto('/events/index/page:9999');

  await expectNoErrorPage(page);
  await expect(main(page).getByRole('heading', { name: 'Events', level: 1 })).toBeVisible();
  await expectScreen(main(page), 'event-index-page-out-of-range.png');
});

test('Event index – search with a single match', async ({ page, api, ts, cleanup }) => {
  const info = `QA unique search 7f3k ${ts}`;
  await api.createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));

  await page.goto('/events/index');
  const search = page.getByRole('textbox', { name: 'Search by info, ID or UUID' });
  await search.fill(info);
  await search.press('Enter');

  await expect(eventIds(page)).toHaveCount(1);
  await expect(row(main(page), info)).toBeVisible();
  await expectScreen(row(main(page), info), 'event-index-search-single.png');
});

test('Event index – combined filters', async ({ page, api, ts, cleanup }) => {
  const names = {
    publishedGreen: `QA filter published green ${ts}`,
    unpublishedGreen: `QA filter unpublished green ${ts}`,
    publishedNoTlp: `QA filter published no tlp ${ts}`,
  };
  await api.createEvent({ info: names.publishedGreen, tags: ['tlp:green'], publish: true });
  await api.createEvent({ info: names.unpublishedGreen, tags: ['tlp:green'] });
  await api.createEvent({ info: names.publishedNoTlp, publish: true });
  for (const info of Object.values(names)) cleanup(() => api.deleteEventsByInfo(info));
  // Publishing runs as a background job.
  await expect.poll(async () => (await api.findEvents(names.publishedGreen))[0]?.published).toBe(true);

  await applyFilters(page, [['tag', 'tlp:green'], ['published', 'Published', /^Published$/]]);

  await expect(row(main(page), names.publishedGreen)).toBeVisible();
  await expect(row(main(page), names.unpublishedGreen)).toHaveCount(0);
  await expect(row(main(page), names.publishedNoTlp)).toHaveCount(0);
  await expectScreen(row(main(page), names.publishedGreen), 'event-index-combined-filters.png');

  // Without the Published filter, the unpublished tlp:green event is listed again.
  await applyFilters(page, [['tag', 'tlp:green']]);
  await expect(row(main(page), names.unpublishedGreen)).toBeVisible();
});

test('Event index – filter kept on the next page', async ({ page, api, ts, cleanup }) => {
  test.setTimeout(180_000);
  const tag = `qa:pw-page-filter-${ts}`;
  await api.createTag(tag);
  cleanup(() => api.deleteTag(tag));
  cleanup(() => api.deleteEventsByTag(tag));
  for (let i = 1; i <= 70; i++) {
    await api.createEvent({ info: `QA page filter ${String(i).padStart(2, '0')} ${ts}`, tags: [tag] });
  }

  await applyFilters(page, [['tag', tag]]);
  await expect(eventIds(page)).toHaveCount(60);
  await main(page).getByRole('navigation', { name: 'Pagination' }).first()
    .getByRole('link', { name: '2', exact: true }).click();

  await expect(page).toHaveURL(/page:2/);
  await expect(eventIds(page)).toHaveCount(10);
  for (const text of await main(page).getByRole('row').allInnerTexts()) {
    if (/#\d+/.test(text)) expect(text).toContain(tag);
  }
  await expectScreen(main(page).getByRole('navigation', { name: 'Pagination' }).first(),
    'event-index-filter-pagination.png');
});
