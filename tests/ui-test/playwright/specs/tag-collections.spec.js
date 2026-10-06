// ../../tag/collection/collections.md
const fs = require('fs');
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, pick, row, rowAction, dialog,
  openEvent, eventCard,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const main = (page) => page.getByRole('main');
const ADMIRALTY_B = 'admiralty-scale:source-reliability="b"';

async function openAddCollection(page) {
  await page.goto('/tag_collections/index');
  await page.getByRole('link', { name: 'Add Tag Collections' }).click();
  return dialog(page);
}

// Creates a collection through the form; returns the form.
async function addCollection(page, name, { tags = [], clusters = [] } = {}) {
  const form = await openAddCollection(page);
  await form.getByRole('textbox', { name: 'e.g. Phishing triage set' }).fill(name);
  for (const tag of tags) await pick(form.getByRole('combobox', { name: 'Search tags to add…' }), tag);
  for (const [search, option] of clusters) {
    await pick(form.getByRole('combobox', { name: 'Search clusters to add…' }), search, option);
  }
  await form.getByRole('button', { name: 'Add Collection' }).click();
  return form;
}

async function searchCollections(page, name) {
  await page.goto('/tag_collections/index');
  const box = page.getByRole('textbox', { name: 'Search by tag collection name' });
  await box.fill(name);
  await box.press('Enter');
  return row(main(page), name);
}

// The tag collection of the "tags and cluster" test, made through the API.
async function seedCollection(api, name) {
  const { TagCollection } = await api.post('/tag_collections/add', {
    TagCollection: { name, description: 'QA test data', all_orgs: false },
  });
  for (const name of ['tlp:green', ADMIRALTY_B, 'misp-galaxy:threat-actor="APT28"']) {
    const tag = await api.findTag(name);
    await api.post(`/tag_collections/addTag/${TagCollection.id}/${tag.id}`);
  }
  return TagCollection;
}

test('Collection add – empty name', async ({ page }) => {
  const form = await openAddCollection(page);
  await form.getByRole('button', { name: 'Add Collection' }).click();

  await expect(form.getByText('Please provide a name for the collection.')).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(form, 'tag-collection-empty-name.png');
});

test('Collection add – tags and cluster', async ({ page, api, ts, cleanup }) => {
  const name = `QA collection ${ts}`;
  cleanup(() => api.deleteTagCollection(name));
  cleanup(await api.enableTaxonomy('admiralty-scale'));
  cleanup(await api.showTag(ADMIRALTY_B));

  await addCollection(page, name, {
    tags: ['tlp:green', ADMIRALTY_B], clusters: [['APT28', /^APT28 Threat Actor$/]],
  });

  const r = await searchCollections(page, name);
  await expect(r).toContainText('tlp:green');
  await expect(r).toContainText(ADMIRALTY_B);
  await expect(r).toContainText('APT28');
  await expectScreen(r, 'tag-collection-add.png', { hide: [ts] });
});

test('Collection add – emoji in the name', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 5 (an emoji in a tag collection name gives "An Internal Error Has Occurred.")');
  const name = `QA collection 🚀 ${ts}`;
  cleanup(() => api.deleteTagCollection(name));

  const form = await addCollection(page, name);
  await expectNoErrorPage(page);
  const r = await searchCollections(page, name);
  await expect(r.or(form.getByText(/emoji|character/i)).first()).toBeVisible();
  await expectScreen(r, 'tag-collection-emoji.png', { hide: [ts] });
});

test('Collection apply to an event', async ({ page, api, ts, cleanup }) => {
  cleanup(await api.enableTaxonomy('admiralty-scale'));
  cleanup(await api.showTag(ADMIRALTY_B));
  const collection = await seedCollection(api, `QA collection ${ts}`);
  cleanup(() => api.deleteTagCollection(collection.name));
  const event = await api.createEvent({ info: `QA collection apply ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  await dialog(page).getByRole('button', { name: 'Tag Collections' }).first().click();
  await pick(dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first(), collection.name);
  await dialog(page).getByRole('button', { name: 'Save Tags' }).click();

  const saved = await api.getEvent(event.id);
  expect(saved.Tag.map((t) => t.name)).toEqual(expect.arrayContaining(['tlp:green', ADMIRALTY_B]));
  expect(JSON.stringify(saved.Galaxy)).toContain('APT28');
  await expect(eventCard(page, 'tags').getByText('tlp:green')).toBeVisible();
  await expectScreen(eventCard(page, 'tags'), 'tag-collection-apply.png');
});

test('Collection apply – exclusive tags', async ({ page, api, ts, cleanup }) => {
  blockedBy('New bug: an exclusive taxonomy is not enforced – tlp:green and tlp:red are both attached '
    + '(also through the API)');
  const name = `QA collection tlp conflict ${ts}`;
  cleanup(() => api.deleteTagCollection(name));
  const event = await api.createEvent({ info: `QA collection conflict ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await addCollection(page, name, { tags: ['tlp:green', 'tlp:red'] });
  await expect.poll(async () => (await searchCollections(page, name)).count()).toBe(1);
  await openEvent(page, event.id);
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  await dialog(page).getByRole('button', { name: 'Tag Collections' }).first().click();
  await pick(dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first(), name);
  await dialog(page).getByRole('button', { name: 'Save Tags' }).click();

  await expectNoErrorPage(page);
  const tlp = ((await api.getEvent(event.id)).Tag || []).filter((t) => t.name.startsWith('tlp:'));
  expect(tlp.map((t) => t.name), 'only one tlp value is attached').toHaveLength(1);
  await expect(page.getByText(/exclusiv/i).first(), 'a message about taxonomy exclusivity').toBeVisible();
  await expectScreen(eventCard(page, 'tags'), 'tag-collection-exclusive.png');
});

test('Collection download configuration', async ({ page, api, ts, cleanup }, testInfo) => {
  const collection = await seedCollection(api, `QA collection ${ts}`);
  cleanup(() => api.deleteTagCollection(collection.name));

  const r = await searchCollections(page, collection.name);
  const pending = page.waitForEvent('download');
  await rowAction(r, 'Download configuration');
  const path = testInfo.outputPath('collection.json');
  await (await pending).saveAs(path);

  const json = JSON.parse(fs.readFileSync(path, 'utf8'));
  const text = JSON.stringify(json);
  for (const value of ['tlp:green', 'source-reliability', 'APT28']) expect(text).toContain(value);
  await expectScreen(r, 'tag-collection-download.png', { hide: [ts] });
});

test('Collection delete – tags kept', async ({ page, api, ts, cleanup }) => {
  const collection = await seedCollection(api, `QA collection ${ts}`);
  cleanup(() => api.deleteTagCollection(collection.name));

  await rowAction(await searchCollections(page, collection.name), 'Delete');
  await dialog(page).getByRole('button', { name: /^Delete/ }).click();
  await expect(await searchCollections(page, collection.name)).toHaveCount(0);

  expect(await api.findTag('tlp:green')).toBeTruthy();
  await page.goto('/tags/index/searchall:tlp%3Agreen');
  await expect(row(main(page), 'tlp:green')).toBeVisible();
  await expectScreen(row(main(page), 'tlp:green'), 'tag-collection-delete.png');
});
