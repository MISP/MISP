// ../../event/edit/edit.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, loginAs,
  openEvent, eventSummary, chooseSlider, dialog, expectAfterReload,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function openEdit(page, eventId) {
  await openEvent(page, eventId);
  await page.getByRole('link', { name: 'Edit Event' }).click();
  return dialog(page);
}

const infoField = (form) => form.getByRole('textbox', { name: /Event Info/ });

test('Event edit – basic fields', async ({ page, api, ts, cleanup }) => {
  const event = await api.createEvent({ info: `QA edit ${ts}` });
  const updated = `QA edit – updated ${ts}`;
  cleanup(() => api.deleteEventsByInfo(updated));
  cleanup(() => api.deleteEventsByInfo(event.info));

  const form = await openEdit(page, event.id);
  await infoField(form).fill(updated);
  await chooseSlider(form, 'Threat level', 'Medium');
  await form.getByRole('button', { name: 'Save Changes' }).click();

  await expect(page).toHaveURL(/\/events\/view2\/\d+/);
  await expect(page.getByRole('heading', { name: updated, level: 1 })).toBeVisible();
  expect((await api.getEvent(event.id)).threat_level_id).toBe('2');
  await expectNoErrorPage(page);
  await expectScreen(eventSummary(page), 'event-edit-basic.png');
});

test('Event edit – future date', async ({ page, api, ts, cleanup }) => {
  const event = await api.createEvent({ info: `QA edit date ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  const form = await openEdit(page, event.id);
  await form.getByRole('textbox', { name: /Event Date/ }).fill('15/06/2030');
  await form.getByRole('button', { name: 'Save Changes' }).click();

  await expect(page).toHaveURL(/\/events\/view2\/\d+/);
  await expectNoErrorPage(page);
  expect((await api.getEvent(event.id)).date).toBe('2030-06-15');
  await expectScreen(eventSummary(page), 'event-edit-future-date.png');
});

test('Event edit – Event Info over the database limit', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 8 (Event Info longer than the database limit gives "An Internal Error Has Occurred.")');
  const event = await api.createEvent({ info: `QA edit long ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  const form = await openEdit(page, event.id);
  await infoField(form).fill('Q'.repeat(70_000));
  await form.getByRole('button', { name: 'Save Changes' }).click();

  await expectNoErrorPage(page);
  await expect(form.getByText(/too long|maximum|characters/i).first()).toBeVisible();
  expect((await api.getEvent(event.id)).info).toBe(event.info);
  await expectScreen(form, 'event-edit-info-too-long.png');
});

test('Event edit – extends itself', async ({ page, api, ts, cleanup }) => {
  blockedBy('New bug: an event can be saved as extending itself ("The event has been saved")');
  const event = await api.createEvent({ info: `QA extends itself ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  const form = await openEdit(page, event.id);
  await form.getByRole('textbox', { name: 'Extends' }).fill(event.id);
  await form.getByRole('button', { name: 'Save Changes' }).click();

  await expectNoErrorPage(page);
  expect((await api.getEvent(event.id)).extends_uuid || '', 'MISP saved the event as extending itself')
    .not.toBe(event.uuid);
  await expect(form.getByText(/extend itself/i).first()).toBeVisible();
  await expectScreen(form, 'event-edit-extends-itself.png');
});

test('Event edit – two tabs at the same time', async ({ page, api, ts, cleanup }) => {
  blockedBy('Missing check: the last save wins, the first tab silently overwrites the second one');
  const event = await api.createEvent({ info: `QA concurrent edit ${ts}` });
  const tab1Info = `QA edit tab 1 ${ts}`;
  const tab2Info = `QA edit tab 2 ${ts}`;
  for (const info of [event.info, tab1Info, tab2Info]) cleanup(() => api.deleteEventsByInfo(info));

  const first = await openEdit(page, event.id);
  const tab2 = await page.context().newPage();
  const second = await openEdit(tab2, event.id);
  await infoField(second).fill(tab2Info);
  await second.getByRole('button', { name: 'Save Changes' }).click();
  await expect(tab2.getByRole('heading', { name: tab2Info, level: 1 })).toBeVisible();

  await infoField(first).fill(tab1Info);
  await first.getByRole('button', { name: 'Save Changes' }).click();

  // Expected: a warning that the event changed meanwhile, not a silent overwrite.
  await expectNoErrorPage(page);
  expect((await api.getEvent(event.id)).info, 'tab 2 was silently overwritten').toBe(tab2Info);
  await expect(page.getByText(/changed|modified|updated/i).filter({ visible: true }).first()).toBeVisible();
  await expectScreen(page.getByRole('main'), 'event-edit-concurrent.png');
});

test('Event edit – event deleted meanwhile', async ({ page, api, ts, cleanup }) => {
  const event = await api.createEvent({ info: `QA edit deleted ${ts}` });
  const changed = `QA edit deleted – changed ${ts}`;
  cleanup(() => api.deleteEventsByInfo(event.info));
  cleanup(() => api.deleteEventsByInfo(changed));

  const form = await openEdit(page, event.id);
  const tab2 = await page.context().newPage();
  await openEvent(tab2, event.id);
  await tab2.getByRole('link', { name: 'Delete Event' }).click();
  await dialog(tab2).getByRole('button', { name: /^Delete/ }).click();
  await expect(tab2).not.toHaveURL(new RegExp(`/events/view2/${event.id}$`));

  await infoField(form).fill(changed);
  await form.getByRole('button', { name: 'Save Changes' }).click();

  await expectNoErrorPage(page);
  await expect(page.getByText(/does not exist|not found|invalid event/i).filter({ visible: true }).first())
    .toBeVisible();
  expect(await api.findEvents(changed), 'no event is re-created').toHaveLength(0);
  await expectScreen(page.getByRole('main'), 'event-edit-deleted.png');
});

test('Event edit – logged out before saving', async ({ browser, api, ts, cleanup }) => {
  const event = await api.createEvent({ info: `QA edit logged out ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  // Its own session: logging out must not end the session the other tests share.
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  cleanup(() => context.close());
  const page = await context.newPage();
  await loginAs(page, 'siteAdmin');
  const form = await openEdit(page, event.id);
  const tab2 = await context.newPage();
  await tab2.goto('/users/logout');
  await expect(tab2).toHaveURL(/\/users\/login/);

  await infoField(form).fill(`QA edit logged out – changed ${ts}`);
  await form.getByRole('button', { name: 'Save Changes' }).click();

  await expect(page).toHaveURL(/\/users\/login/);
  await expectNoErrorPage(page);
  expect((await api.getEvent(event.id)).info).toBe(event.info);
  // The login page itself keeps moving: capture its sign-in form only.
  await expectScreen(page.locator('form').filter({ has: page.getByRole('button', { name: 'Login' }) }),
    'event-edit-logged-out.png');
});

test('Event edit – published event', async ({ page, api, ts, cleanup }) => {
  const event = await api.createEvent({ info: `QA edit published ${ts}`, publish: true });
  const changed = `QA edit published – changed ${ts}`;
  cleanup(() => api.deleteEventsByInfo(event.info));
  cleanup(() => api.deleteEventsByInfo(changed));

  await openEvent(page, event.id);
  // Publishing runs as a background job.
  await expectAfterReload(page, () => expect(page.getByRole('main')).toContainText(/Publication\s*Published/));
  const form = await openEdit(page, event.id);
  await infoField(form).fill(changed);
  await form.getByRole('button', { name: 'Save Changes' }).click();

  await expect(page.getByRole('heading', { name: changed, level: 1 })).toBeVisible();
  await expect(page.getByRole('main')).toContainText(/Publication\s*Unpublished/);
  await expect(page.getByRole('link', { name: 'Publish Event' })).toBeVisible();
  await expectScreen(eventSummary(page), 'event-edit-published.png');
});

test('Event edit – empty Event Info', async ({ page, api, ts, cleanup }) => {
  const event = await api.createEvent({ info: `QA edit empty info ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  const form = await openEdit(page, event.id);
  await infoField(form).fill('');
  await form.getByRole('button', { name: 'Save Changes' }).click();

  await expect(form.getByText('Please provide a name for the event.')).toBeVisible();
  await expect(form).toBeVisible();
  expect((await api.getEvent(event.id)).info).toBe(event.info);
  await expectScreen(form, 'event-edit-empty-info.png');
});
