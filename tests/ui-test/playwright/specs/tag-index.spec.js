// ../../tag/index/tags.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, pick, row, rowAction, dialog,
  openEvent, eventCard,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const main = (page) => page.getByRole('main');
const nameField = (form) => form.getByRole('textbox', { name: 'e.g. tlp:red or malware:apt' });

async function openAddTag(page) {
  await page.goto('/tags/index');
  await page.getByRole('link', { name: /^Add Tag/ }).first().click();
  return dialog(page);
}

async function addTagUi(page, name, { hidden, exportable = true, colour } = {}) {
  const form = await openAddTag(page);
  await nameField(form).fill(name);
  if (colour) await form.locator('#TagColourHex').fill(colour);
  if (hidden) await form.getByRole('checkbox', { name: /^Hidden/ }).check();
  if (!exportable) await form.getByRole('checkbox', { name: /^Exportable/ }).uncheck();
  await form.getByRole('button', { name: 'Add Tag' }).click();
  return form;
}

async function searchTags(page, text) {
  await page.goto('/tags/index');
  const box = page.getByRole('textbox', { name: 'Search by tag name' });
  await box.fill(text);
  await box.press('Enter');
}

// Edit Tags on an event page: add a global tag and save.
async function tagEvent(page, tag) {
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  await pick(dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first(), tag);
  await dialog(page).getByRole('button', { name: 'Save Tags' }).click();
  await expect(eventCard(page, 'tags').getByText(tag)).toBeVisible();
}

test('Tag add – custom tag', async ({ page, api, ts, cleanup }) => {
  const tag = `qa:custom-${ts}`;
  cleanup(() => api.deleteTag(tag));
  const event = await api.createEvent({ info: `QA custom tag ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await addTagUi(page, tag);
  await searchTags(page, tag);
  await expect(row(main(page), tag)).toBeVisible();

  await openEvent(page, event.id);
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  await dialog(page).getByRole('button', { name: 'Custom Tags' }).first().click();
  const combobox = dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first();
  await combobox.click();
  await page.keyboard.type(tag);
  await expect(page.getByRole('option', { name: tag })).toBeVisible();
  await expectScreen(dialog(page), 'tag-add-custom.png');
});

test('Tag add – empty name', async ({ page }) => {
  const form = await openAddTag(page);
  await form.getByRole('button', { name: 'Add Tag' }).click();

  await expect(form.getByText('Please provide a name for the tag.')).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(form, 'tag-add-empty.png');
});

test('Tag add – same name with other case', async ({ page, api, ts, cleanup }) => {
  blockedBy('New bug: a duplicate tag is refused but the form closes with no message');
  const tag = `qa:case-${ts}`;
  cleanup(() => api.deleteTag(tag));
  cleanup(() => api.deleteTag(tag.toUpperCase()));

  await addTagUi(page, tag);
  await expect.poll(() => api.findTag(tag)).toBeTruthy();
  const form = await addTagUi(page, tag.toUpperCase());
  const message = 'A similar name already exists.';
  await Promise.race([form.getByText(message).first().waitFor(), form.waitFor({ state: 'hidden' })]);

  expect(await api.findTag(tag.toUpperCase()), 'MISP created the duplicate').toBeUndefined();
  expect(await form.isVisible(), 'MISP closed the form with no message').toBe(true);
  await expect(form.getByText(message)).toBeVisible();
  await expectScreen(form, 'tag-add-case-duplicate.png');
});

test('Tag add – name longer than 255 characters', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 19 (a tag name longer than 255 characters is silently cut)');
  const tag = `qa:${ts}-${'x'.repeat(300)}`.slice(0, 300);
  cleanup(() => api.deleteTag(tag.slice(0, 255)));

  const form = await addTagUi(page, tag);
  await Promise.race([form.getByText(/too long|255|maximum/i).first().waitFor(), form.waitFor({ state: 'hidden' })]);

  expect(await api.findTag(tag.slice(0, 255)), 'MISP created the tag with a cut name').toBeUndefined();
  await expect(form.getByText(/too long|255|maximum/i).first()).toBeVisible();
  await expectScreen(form, 'tag-add-too-long.png');
});

test('Tag add – invalid colour', async ({ page, api, ts, cleanup }) => {
  blockedBy('New bug: an invalid colour is ignored – the tag is saved with another colour and "Tag added."');
  const tag = `qa:colour-${ts}`;
  cleanup(() => api.deleteTag(tag));

  const form = await addTagUi(page, tag, { colour: '#12' });
  await Promise.race([form.getByText(/colou?r/i).first().waitFor(), form.waitFor({ state: 'hidden' })]);

  const created = await api.findTag(tag);
  expect(created, `MISP created the tag with the colour ${created?.colour} instead of refusing #12`)
    .toBeUndefined();
  await expect(form.getByText(/invalid.*colou?r|colou?r.*invalid/i).first()).toBeVisible();
  await expectScreen(form, 'tag-add-invalid-colour.png');
});

test('Tag search with a colon', async ({ page }) => {
  await searchTags(page, 'tlp:');

  await expect(row(main(page), 'tlp:green')).toBeVisible();
  await expect(row(main(page), 'tlp:red')).toBeVisible();
  await expectScreen(row(main(page), 'tlp:green'), 'tag-search-colon.png');
});

test('Tag rename – used on an event', async ({ page, api, ts, cleanup }) => {
  const oldName = `qa:old-name-${ts}`;
  const newName = `qa:new-name-${ts}`;
  await api.createTag(oldName);
  cleanup(() => api.deleteTag(oldName));
  cleanup(() => api.deleteTag(newName));
  const event = await api.createEvent({ info: `QA tag rename ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  await tagEvent(page, oldName);
  await searchTags(page, oldName);
  await rowAction(row(main(page), oldName), 'Edit');
  await nameField(dialog(page)).fill(newName);
  await dialog(page).getByRole('button', { name: /Save Changes|Edit Tag|Save/ }).click();

  await openEvent(page, event.id);
  await expect(eventCard(page, 'tags').getByText(newName)).toHaveCount(1);
  await expect(eventCard(page, 'tags').getByText(oldName)).toHaveCount(0);
  await expectNoErrorPage(page);
  await expectScreen(eventCard(page, 'tags'), 'tag-rename-used.png', { hide: [ts] });
});

test('Tag delete – used on an event', async ({ page, api, ts, cleanup }) => {
  const tag = `qa:to-delete-${ts}`;
  await api.createTag(tag);
  cleanup(() => api.deleteTag(tag));
  const event = await api.createEvent({ info: `QA tag delete ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  await tagEvent(page, tag);
  await searchTags(page, tag);
  await rowAction(row(main(page), tag), 'Delete');
  await dialog(page).getByRole('button', { name: /^Delete/ }).click();

  await openEvent(page, event.id);
  await expectNoErrorPage(page);
  await expect(eventCard(page, 'tags').getByText(tag)).toHaveCount(0);
  await expectScreen(eventCard(page, 'tags'), 'tag-delete-used.png');
});

test('Tag hidden', async ({ page, api, ts, cleanup }) => {
  const tag = `qa:hidden-${ts}`;
  cleanup(() => api.deleteTag(tag));
  const event = await api.createEvent({ info: `QA hidden tag ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await addTagUi(page, tag, { hidden: true });
  await expect.poll(() => api.findTag(tag)).toBeTruthy();
  await openEvent(page, event.id);
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  await dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first().click();
  await page.keyboard.type(tag);

  await expect(page.getByRole('option', { name: tag })).toHaveCount(0);
  await expectScreen(dialog(page), 'tag-hidden.png', { hide: [ts] });
});

test('Tag not exportable', async ({ page, api, ts, cleanup }) => {
  const tag = `qa:no-export-${ts}`;
  cleanup(() => api.deleteTag(tag));
  const event = await api.createEvent({ info: `QA not exportable ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await addTagUi(page, tag, { exportable: false });
  await expect.poll(() => api.findTag(tag)).toBeTruthy();
  await openEvent(page, event.id);
  await tagEvent(page, tag);

  const json = await (await page.request.get(`/events/view/${event.id}.json`)).text();
  expect(json).toContain(event.uuid);
  expect(json).not.toContain(tag);
  await expectScreen(eventCard(page, 'tags'), 'tag-not-exportable.png', { hide: [ts] });
});

test('Tag list – Not favourite filter', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 20 (the "Not favourite" filter still shows favourite tags)');
  const tag = `qa:favourite-${ts}`;
  const created = await api.createTag(tag);
  cleanup(() => api.deleteTag(tag));

  await searchTags(page, tag);
  await row(main(page), tag).locator('.tag-star').click();
  await expect(row(main(page), tag).locator('.tag-star.fas')).toBeVisible();
  cleanup(async () => {
    if (await api.findTag(tag)) await api.post('/favourite_tags/toggle', { FavouriteTag: { data: created.id } });
  });

  const filterOn = async (option) => {
    await page.getByRole('button', { name: 'More filters' }).click();
    await pick(page.locator('select[name=favouritesOnly] + .ts-wrapper').getByRole('combobox'), option);
    await page.getByRole('button', { name: 'Apply filters' }).click();
  };
  await filterOn('Not favourite');
  await expect(row(main(page), tag)).toHaveCount(0);
  await filterOn('Favourite only');
  await expect(row(main(page), tag)).toBeVisible();
  await expectScreen(row(main(page), tag), 'tag-index-not-favourite.png', { hide: [ts] });
});
