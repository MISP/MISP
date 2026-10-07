// ../../analyst-data/notes/notes.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, openEvent, dialog,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const NOTE_NAME = 'Write your analysis note…';

function analystData(page) {
  return page.locator('#analyst-data-card');
}

// The note or opinion box whose own text is `text` (not one of its parents).
function item(page, text) {
  return analystData(page).getByText(text, { exact: true })
    .locator('xpath=ancestor::div[contains(@class,"ov-ad-nested")][1]');
}

async function newEvent(api, cleanup, info) {
  cleanup(() => api.deleteEventsByInfo(info));
  return api.createEvent({ info });
}

async function createNote(page, text, parent) {
  if (parent) {
    await item(page, parent).getByRole('button', { name: 'Add analyst data' }).first().click();
    await page.locator('.dropdown-menu.show').getByRole('link', { name: 'Add note' }).click();
  } else {
    await analystData(page).getByRole('button', { name: 'Add note' }).click();
  }
  const form = dialog(page);
  await expect(form.getByRole('heading', { name: 'Add Note' })).toBeVisible();
  await form.getByRole('textbox', { name: NOTE_NAME }).fill(text);
  await form.getByRole('button', { name: 'Create Note' }).click();
  return form;
}

test('Note – add without text', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 12 (a note can be saved without its required text)');
  const event = await newEvent(api, cleanup, `QA analyst note ${ts}`);

  await openEvent(page, event.id);
  const form = await createNote(page, '');
  await expect(form.getByText(/is required|cannot be empty|please (provide|enter|fill)/i).first()).toBeVisible();
  await expect(page.getByText('Note added.')).toHaveCount(0);
  await expect(analystData(page).getByText(/^Notes \(/)).toHaveCount(0);
  await expectNoErrorPage(page);
  await expectScreen(form, 'analyst-note-add-empty.png');
});

test('Note – edit to an empty text', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 12 (a note can be saved with an empty text)');
  const event = await newEvent(api, cleanup, `QA analyst note ${ts}`);

  await openEvent(page, event.id);
  await createNote(page, 'QA note text');
  await expect(page.getByText('Note added.')).toBeVisible();
  await item(page, 'QA note text').getByRole('link', { name: 'Edit' }).first().click();
  const form = dialog(page);
  await expect(form.getByRole('heading', { name: 'Edit Note' })).toBeVisible();
  await form.getByRole('textbox', { name: NOTE_NAME }).fill('');
  await form.getByRole('button', { name: 'Save changes' }).click();
  await expect(form.getByText(/is required|cannot be empty|please (provide|enter|fill)/i).first()).toBeVisible();
  await openEvent(page, event.id);
  await expect(item(page, 'QA note text')).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(item(page, 'QA note text'), 'analyst-note-edit-empty.png');
});

test('Note – add with text', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA analyst note ${ts}`);

  await openEvent(page, event.id);
  await createNote(page, 'QA analyst note text');
  await expect(page.getByText('Note added.')).toBeVisible();
  await openEvent(page, event.id);
  await expect(analystData(page).getByText('Notes (1)')).toBeVisible();
  await expect(item(page, 'QA analyst note text')).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(analystData(page), 'analyst-note-add.png');
});

test('Note – four nested levels', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA nested notes ${ts}`);
  const levels = ['QA level 1', 'QA level 2', 'QA level 3', 'QA level 4'];

  await openEvent(page, event.id);
  for (const [i, text] of levels.entries()) {
    await createNote(page, text, levels[i - 1]);
    await expect(page.getByText('Note added.').last()).toBeVisible();
    // Wait for the block to show the note before answering it.
    if (i < 2) await expect(item(page, text)).toBeVisible();
    else await openEvent(page, event.id);
  }
  // Every note exists, attached to the previous one.
  const notes = await api.get(`/analystData/index/Note`);
  const byText = Object.fromEntries((notes.map((n) => n.Note || n))
    .filter((n) => levels.includes(n.note)).slice(-4).map((n) => [n.note, n]));
  for (let i = 1; i < 4; i += 1) {
    expect(byText[levels[i]].object_uuid).toBe(byText[levels[i - 1]].uuid);
  }

  blockedBy('Bug 16 (the 4th level of nested notes is not shown on the event page)');
  await page.reload();
  for (let i = 1; i < 4; i += 1) {
    await expect(item(page, levels[i - 1]).getByText(levels[i], { exact: true })).toBeVisible();
  }
  await expectNoErrorPage(page);
  await expectScreen(analystData(page), 'analyst-note-nested.png');
});

test('Analyst data – counters with nested items', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA nested notes ${ts}`);
  let parent = { uuid: event.uuid, type: 'Event' };
  for (const level of [1, 2, 3, 4]) {
    const note = await api.addNote(parent.uuid, parent.type, `QA level ${level}`);
    parent = { uuid: note.uuid, type: 'Note' };
  }

  await openEvent(page, event.id);
  for (const comment of ['QA opinion 1', 'QA opinion 2']) {
    await analystData(page).getByRole('button', { name: 'Add opinion' }).click();
    const form = dialog(page);
    await expect(form.getByRole('heading', { name: 'Add Opinion' })).toBeVisible();
    await form.getByRole('textbox', { name: 'Justify your opinion…' }).fill(comment);
    await form.getByRole('button', { name: 'Create Opinion' }).click();
    await expect(form).toBeHidden();
    await openEvent(page, event.id);
    await expect(item(page, comment)).toBeVisible();
  }
  await createNote(page, 'QA note on opinion', 'QA opinion 1');
  await expect(page.getByText('Note added.')).toBeVisible();
  await openEvent(page, event.id);

  blockedBy('Bug 16 (the Notes and Opinions counters only count the first level)');
  // 4 nested notes + 1 note on an opinion; 2 opinions.
  await expect(analystData(page).getByText('Notes (5)')).toBeVisible();
  await expect(analystData(page).getByText('Opinions (2)')).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(analystData(page), 'analyst-data-counters.png');
});
