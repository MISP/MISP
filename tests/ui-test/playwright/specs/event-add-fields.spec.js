// ../../event/add/fields.md
const {
  test, expect, expectNoErrorPage, expectScreen, chooseSlider, openTab, row,
  eventSummary,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const today = new Date().toISOString().slice(0, 10);

// Opens the Add Event window from the Events list and types the Event Info.
async function openAddEvent(page, info) {
  await page.goto('/events/index');
  await page.getByRole('link', { name: 'Add Event' }).click();
  const form = page.getByRole('dialog');
  if (info !== undefined) await form.getByRole('textbox', { name: /Event Info/ }).fill(info);
  return form;
}

async function submit(form) {
  await form.getByRole('button', { name: 'Create Event Entry' }).click();
}

async function expectEventPage(page, info) {
  await expect(page).toHaveURL(/\/events\/view2\/\d+/);
  await expect(page.getByRole('heading', { name: info, level: 1 })).toBeVisible();
  await expectNoErrorPage(page);
}

const main = (page) => page.getByRole('main');

test('Event add', async ({ page, api, ts, cleanup }) => {
  const info = `QA event add ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));

  const form = await openAddEvent(page, info);
  await form.getByRole('textbox', { name: /Event Date/ }).fill('01/09/2026');
  await submit(form);

  await expectEventPage(page, info);
  await expect(main(page).getByText('2026-09-01', { exact: true })).toBeVisible();
  await expectScreen(eventSummary(page), 'event-add.png');
});

test('Event add – minimal fields', async ({ page, api, ts, cleanup }) => {
  const info = `QA minimal event ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));

  await submit(await openAddEvent(page, info));

  await expectEventPage(page, info);
  await expect(main(page).getByText(today, { exact: true })).toBeVisible();
  const [{ id }] = await api.findEvents(info);
  const event = await api.getEvent(id);
  expect([event.date, event.distribution, event.analysis, event.published])
    .toEqual([today, '1', '0', false]);
  await expectScreen(eventSummary(page), 'event-add-minimal.png');
});

test('Event add – future date', async ({ page, api, ts, cleanup }) => {
  const info = `QA future date ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));

  const form = await openAddEvent(page, info);
  await form.getByRole('textbox', { name: /Event Date/ }).fill('15/06/2030');
  await submit(form);

  await expectEventPage(page, info);
  await expect(main(page).getByText('2030-06-15', { exact: true })).toBeVisible();
  await expectScreen(eventSummary(page), 'event-add-future-date.png');
});

test('Event add – all fields set', async ({ page, api, ts, cleanup }) => {
  const info = `QA all fields ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));

  const form = await openAddEvent(page, info);
  await form.getByRole('radio', { name: /^All communities/ }).check();
  await chooseSlider(form, 'Analysis level', 'Completed');
  await chooseSlider(form, 'Threat level', 'High');
  await form.getByRole('textbox', { name: /Event Date/ }).fill('01/09/2026');
  await submit(form);

  await expectEventPage(page, info);
  await expect(main(page).getByText('All communities', { exact: true })).toBeVisible();
  await expect(main(page).getByText('2026-09-01', { exact: true })).toBeVisible();
  const [{ id }] = await api.findEvents(info);
  const event = await api.getEvent(id);
  expect([event.distribution, event.analysis, event.threat_level_id, event.date])
    .toEqual(['3', '2', '1', '2026-09-01']);
  await expectScreen(eventSummary(page), 'event-add-all-fields.png');
});

test('Event add – distribution levels', async ({ page, api, ts, cleanup }) => {
  const info = `QA distribution ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));
  const { response: groups } = await api.get('/sharing_groups/index');

  const form = await openAddEvent(page);
  await expectScreen(form, 'add-event-form.png');
  for (const level of ['Your organisation only', 'This community only',
    'Connected communities', 'All communities']) {
    await expect(form.getByRole('radio', { name: new RegExp(`^${level}`) })).toBeVisible();
  }
  await expect(form.getByRole('radio', { name: /^Sharing group/ })).toHaveCount(groups.length ? 1 : 0);
  await form.getByRole('textbox', { name: /Event Info/ }).fill(info);
  await form.getByRole('radio', { name: /^This community only/ }).check();
  await submit(form);

  await expectEventPage(page, info);
  await expect(main(page).getByText('This community only', { exact: true })).toBeVisible();
  await expectScreen(eventSummary(page), 'event-add-distribution.png');
});

test('Event add – extends an existing event', async ({ page, api, ts, cleanup }) => {
  const info = `QA extends event ${ts}`;
  const parent = await api.createEvent({ info: `QA extended parent ${ts}` });
  cleanup(() => api.deleteEventsByInfo(parent.info));
  cleanup(() => api.deleteEventsByInfo(info));

  const form = await openAddEvent(page, info);
  await form.getByRole('textbox', { name: 'Extends' }).fill(parent.id);
  await expect(form.getByText(parent.info)).toBeVisible();
  await submit(form);

  await expectEventPage(page, info);
  // The extended event is listed in the "More details" part of the event summary.
  await main(page).getByRole('button', { name: 'More details' }).click();
  await expect(main(page).getByText(parent.info).first()).toBeVisible();
  await expectScreen(eventSummary(page), 'event-add-extends.png');
});

test('Event add – HTML in Event Info', async ({ page, api, ts, cleanup }) => {
  const info = `<script>alert(1)</script><b>QA</b> ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));
  const dialogs = [];
  page.on('dialog', (d) => { dialogs.push(d.message()); d.dismiss(); });

  await submit(await openAddEvent(page, info));
  await expectEventPage(page, info);

  await page.goto('/events/index');
  await expect(row(main(page), info)).toBeVisible();
  expect(dialogs, 'no alert pops up').toEqual([]);
  await expect(page.locator('main b', { hasText: /^QA$/ })).toHaveCount(0);
  await expectScreen(row(main(page), info), 'event-add-html-row.png');
});

test('Event add – extends an unknown UUID', async ({ page, api, ts, cleanup }) => {
  const info = `QA extends unknown UUID ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));

  const form = await openAddEvent(page, info);
  await form.getByRole('textbox', { name: 'Extends' }).fill('7c9e6679-7425-40de-944b-e07fc1f90ae7');
  await submit(form);

  // Created, or refused with a clear message: never an error page.
  await expectNoErrorPage(page);
  if (/\/events\/view2\/\d+/.test(page.url())) {
    await expectEventPage(page, info);
  } else {
    await expect(form.locator('.invalid-feedback').filter({ visible: true })).not.toHaveCount(0);
  }
  await expectScreen(eventSummary(page), 'event-add-extends-unknown-uuid.png');
});

test('Event add – Event Info with line breaks', async ({ page, api, ts, cleanup }) => {
  const info = `QA line 1 ${ts}\nQA line 2`;
  cleanup(() => api.deleteEventsByInfo(info));

  const form = await openAddEvent(page);
  const field = form.getByRole('textbox', { name: /Event Info/ });
  await field.fill(`QA line 1 ${ts}`);
  await field.press('Shift+Enter');
  await field.pressSequentially('QA line 2');
  await submit(form);

  await expect(page).toHaveURL(/\/events\/view2\/\d+/);
  await expect(page.getByRole('heading', { level: 1 })).toContainText(`QA line 1 ${ts}`);
  await expect(page.getByRole('heading', { level: 1 })).toContainText('QA line 2');
  await page.goto('/events/index');
  await expect(main(page).getByRole('row').filter({ hasText: `QA line 1 ${ts}` })).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(main(page).getByRole('row').filter({ hasText: `QA line 1 ${ts}` }), 'event-add-multiline-row.png');
});

test('Event add – extreme dates', async ({ page, api, ts, cleanup }) => {
  for (const [label, typed, stored] of [
    ['1900', '01/01/1900', '1900-01-01'], ['9999', '31/12/9999', '9999-12-31'],
  ]) {
    const info = `QA date ${label} ${ts}`;
    cleanup(() => api.deleteEventsByInfo(info));
    await test.step(`date ${typed}`, async () => {
      const form = await openAddEvent(page, info);
      await form.getByRole('textbox', { name: /Event Date/ }).fill(typed);
      await submit(form);
      await expectNoErrorPage(page);
      if (/\/events\/view2\/\d+/.test(page.url())) {
        await expect(main(page).getByText(stored, { exact: true })).toBeVisible();
      } else {
        await expect(form.locator('.invalid-feedback').filter({ visible: true })).not.toHaveCount(0);
      }
    });
  }
  await expectScreen(eventSummary(page), 'event-add-extreme-dates.png');
});
