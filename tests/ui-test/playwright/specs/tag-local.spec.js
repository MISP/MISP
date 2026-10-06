// ../../tag/local/local.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, pick, row, dialog, openEvent, eventCard,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

// Edit Tags on an event page: `global` or `local` section, then Save Tags.
async function addTag(page, tag, section) {
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  const pickers = dialog(page).getByRole('combobox', { name: 'Search tags to add…' });
  await pick(section === 'local' ? pickers.nth(1) : pickers.first(), tag);
  await dialog(page).getByRole('button', { name: 'Save Tags' }).click();
}

async function newEvent(page, api, cleanup, info) {
  const event = await api.createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));
  await openEvent(page, event.id);
  return event;
}

const tagsOf = async (api, event) => ((await api.getEvent(event.id)).Tag || [])
  .map((t) => [t.name, t.local === true || t.local === 1 || t.local === '1']);

test('Local tag on an event', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(page, api, cleanup, `QA local tag ${ts}`);
  await addTag(page, 'tlp:green', 'local');

  await expect(page.getByText('Tags updated.')).toBeVisible();
  expect(await tagsOf(api, event)).toEqual([['tlp:green', true]]);
  await expectScreen(eventCard(page, 'tags'), 'tag-local-add.png');
});

test('Local-only tag as a global tag', async ({ page, api, ts, cleanup }) => {
  const tag = `qa:local-only-${ts}`;
  await api.post('/tags/add', { Tag: { name: tag, colour: '#7c3aed', local_only: true } });
  cleanup(() => api.deleteTag(tag));
  const event = await newEvent(page, api, cleanup, `QA local only global ${ts}`);
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  await dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first().click();
  await page.keyboard.type(tag);
  await page.waitForTimeout(1_000);

  // Not offered under Global Tags at all: the mistake cannot be made.
  await expect(page.getByRole('option', { name: tag })).toHaveCount(0);
  expect(await tagsOf(api, event)).toEqual([]);
  await page.keyboard.press('Escape');
  await expectScreen(eventCard(page, 'tags'), 'tag-local-only-global.png');
});

test('Local-only tag as a local tag', async ({ page, api, ts, cleanup }) => {
  blockedBy('New bug: a local-only tag is never offered in Edit Tags, not even under Local Tags');
  const tag = `qa:local-only-ok-${ts}`;
  await api.post('/tags/add', { Tag: { name: tag, colour: '#7c3aed', local_only: true } });
  cleanup(() => api.deleteTag(tag));
  const event = await newEvent(page, api, cleanup, `QA local only local ${ts}`);
  await addTag(page, tag, 'local');

  await expectNoErrorPage(page);
  expect(await tagsOf(api, event)).toEqual([[tag, true]]);
  await expectScreen(eventCard(page, 'tags'), 'tag-local-only-local.png', { hide: [ts] });
});

test('Local-only tag on several events at once', async ({ page, api, ts, cleanup }) => {
  blockedBy('Missing feature: the selection toolbar of the Events list has no tag action (only Export and Delete)');
  const names = [`QA local bulk 1 ${ts}`, `QA local bulk 2 ${ts}`];
  for (const info of names) {
    await api.createEvent({ info });
    cleanup(() => api.deleteEventsByInfo(info));
  }

  await page.goto('/events/index');
  for (const info of names) await row(page.getByRole('main'), info).getByRole('checkbox').check();
  await expect(page.getByRole('button', { name: /tag/i }).filter({ visible: true }).first(),
    'a tag action in the selection toolbar').toBeVisible({ timeout: 5_000 });
});

test('Events list – filter by local tag', async ({ page, api, ts, cleanup }) => {
  const tag = 'admiralty-scale:source-reliability="a"';
  cleanup(await api.enableTaxonomy('admiralty-scale'));
  cleanup(await api.showTag(tag));
  const event = await newEvent(page, api, cleanup, `QA local filter ${ts}`);
  await addTag(page, tag, 'local');
  await expect(eventCard(page, 'tags').getByText(tag)).toBeVisible();

  await page.goto('/events/index');
  await page.getByRole('button', { name: 'More filters' }).click();
  await pick(page.locator('select[name=tag] + .ts-wrapper').getByRole('combobox'), tag);
  await page.getByRole('button', { name: 'Apply filters' }).click();

  await expect(row(page.getByRole('main'), event.info)).toBeVisible();
  await expectScreen(row(page.getByRole('main'), event.info), 'tag-local-filter.png');
});
