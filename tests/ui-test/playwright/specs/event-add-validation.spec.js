// ../../event/add/validation.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function openAddEvent(page) {
  await page.goto('/events/index');
  await page.getByRole('link', { name: 'Add Event' }).click();
  return page.getByRole('dialog');
}

// The form is refused: no new event, the window stays open, `message` is shown.
async function expectRefused(page, form, api, info, message) {
  await expect(form.getByText(message)).toBeVisible();
  await expect(form).toBeVisible();
  await expect(page).toHaveURL(/\/events\/index/);
  if (info.trim()) expect(await api.findEvents(info)).toHaveLength(0);
  await expectNoErrorPage(page);
}

test('Event add – empty Event Info', async ({ page, api }) => {
  const form = await openAddEvent(page);
  await form.getByRole('button', { name: 'Create Event Entry' }).click();
  await expectRefused(page, form, api, '', 'Please provide a name for the event.');
  await expectScreen(form, 'event-add-empty-info.png');
});

test('Event add – Event Info with only spaces', async ({ page, api }) => {
  const form = await openAddEvent(page);
  const info = form.getByRole('textbox', { name: /Event Info/ });
  await info.fill('     ');
  await form.getByRole('button', { name: 'Create Event Entry' }).click();
  await expectRefused(page, form, api, '', 'Please provide a name for the event.');
  await expectScreen(form, 'event-add-spaces-info.png');
});

test('Event add – invalid date', async ({ page, api, ts }) => {
  const info = `QA invalid date ${ts}`;
  const form = await openAddEvent(page);
  await form.getByRole('textbox', { name: /Event Info/ }).fill(info);
  await form.getByRole('textbox', { name: /Event Date/ }).fill('31/02/2026');
  await form.getByRole('button', { name: 'Create Event Entry' }).click();
  await expectRefused(page, form, api, info, 'Enter the event date as DD/MM/YYYY.');
  await expectScreen(form, 'event-add-invalid-date.png');
});

test('Event add – extends an unknown event ID', async ({ page, api, ts, cleanup }) => {
  blockedBy('New bug: an unknown Extends ID sends the user to the home page with only "The event '
    + 'could not be saved. Please, try again." – the form and its values are lost');
  const info = `QA extends unknown ID ${ts}`;
  const form = await openAddEvent(page);
  await form.getByRole('textbox', { name: /Event Info/ }).fill(info);
  await form.getByRole('textbox', { name: 'Extends' }).fill('999999');
  await form.getByRole('button', { name: 'Create Event Entry' }).click();
  cleanup(() => api.deleteEventsByInfo(info));
  await expectRefused(page, form, api, info, 'Invalid event ID provided.');
  await expect(form.getByRole('textbox', { name: /Event Info/ })).toHaveValue(info);
  await expectScreen(form, 'event-add-extends-unknown-id.png');
});

test('Event add – Event Info over the database limit', async ({ page }) => {
  blockedBy('Bug 8 (Event Info longer than the database limit gives "An Internal Error Has Occurred.")');
  const form = await openAddEvent(page);
  await form.getByRole('textbox', { name: /Event Info/ }).fill('Q'.repeat(70_000));
  await form.getByRole('button', { name: 'Create Event Entry' }).click();
  await expectNoErrorPage(page);
  await expect(form.getByText(/too long|maximum|characters/i).first()).toBeVisible();
  await expect(page).not.toHaveURL(/\/events\/view2\//);
  await expectScreen(form, 'event-add-info-too-long.png');
});
