// ../../taxonomy/tagging/exclusive.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, pick, row, dialog, openEvent, openTab, eventCard,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function editTags(page, add, remove) {
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  if (remove) await dialog(page).getByRole('button', { name: 'Remove' }).first().click();
  if (add) await pick(dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first(), add);
  await dialog(page).getByRole('button', { name: 'Save Tags' }).click();
}

const tlpOf = async (api, event) => ((await api.getEvent(event.id)).Tag || [])
  .map((t) => t.name).filter((n) => n.startsWith('tlp:'));

test('Exclusive taxonomy – two values on one event', async ({ page, api, ts, cleanup }) => {
  blockedBy('New bug: an exclusive taxonomy is not enforced – tlp:green and tlp:red are both attached');
  const event = await api.createEvent({ info: `QA exclusive tlp ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  await editTags(page, 'tlp:green');
  await expect(eventCard(page, 'tags').getByText('tlp:green')).toBeVisible();
  await editTags(page, 'tlp:red');

  expect(await tlpOf(api, event), 'the event keeps only tlp:green').toEqual(['tlp:green']);
  await expect(page.getByText(/exclusiv/i).first()).toBeVisible();
  await expectScreen(eventCard(page, 'tags'), 'taxonomy-exclusive-two-tags.png');
});

test('Exclusive taxonomy – replace a value', async ({ page, api, ts, cleanup }) => {
  const event = await api.createEvent({ info: `QA exclusive replace ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  await editTags(page, 'tlp:green');
  await expect(eventCard(page, 'tags').getByText('tlp:green')).toBeVisible();
  await editTags(page, null, true);
  await expect(eventCard(page, 'tags').getByText('tlp:green')).toHaveCount(0);
  await editTags(page, 'tlp:red');

  await expectNoErrorPage(page);
  expect(await tlpOf(api, event)).toEqual(['tlp:red']);
  await expectScreen(eventCard(page, 'tags'), 'taxonomy-exclusive-replace.png');
});

test('Exclusive taxonomy – event and attribute', async ({ page, api, ts, cleanup }) => {
  const event = await api.createEvent({
    info: `QA exclusive attribute ${ts}`,
    attributes: [{ type: 'ip-dst', category: 'Network activity', value: '198.51.100.10' }],
  });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  await editTags(page, 'tlp:green');
  const attributes = await openTab(page, 'Attributes');
  await row(attributes, '198.51.100.10').getByRole('button', { name: 'Add a tag' }).click();
  await pick(dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first(), 'tlp:red');
  await dialog(page).getByRole('button', { name: 'Save Tags' }).click();

  // Accepted, or refused with a clear message: never an error page.
  await expectNoErrorPage(page);
  const attribute = (await api.getEvent(event.id)).Attribute[0];
  if (!(attribute.Tag || []).some((t) => t.name === 'tlp:red')) {
    await expect(page.getByText(/exclusiv|not allowed|tlp/i).first()).toBeVisible();
  }
  await expectScreen(row(page.getByRole('tabpanel').filter({ visible: true }), '198.51.100.10'),
    'taxonomy-exclusive-event-attribute.png');
});
