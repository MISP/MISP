// ../../event/view/actions.md
const {
  test, expect, expectNoErrorPage, expectScreen, blockedBy, openEvent, row, pick, dialog,
  eventSummary, eventCard, expectAfterReload,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const main = (page) => page.getByRole('main');

test('Event publish and unpublish', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 9 (Unpublish Event opens the old event page /events/view/<id>)');
  const event = await api.createEvent({ info: `QA publish ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await test.step('publish', async () => {
    await openEvent(page, event.id);
    await page.getByRole('link', { name: 'Publish Event' }).click();
    await dialog(page).getByRole('button', { name: 'Publish', exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/events/view2/${event.id}$`));
    await expectAfterReload(page, () => expect(main(page)).toContainText(/Publication\s*Published/));
  });

  await test.step('unpublish', async () => {
    await page.goto('/events/index');
    await openEvent(page, event.id);
    await page.getByRole('link', { name: 'Unpublish Event' }).click();
    await dialog(page).getByRole('button', { name: /^Unpublish/ }).click();
    await expect(page).toHaveURL(new RegExp(`/events/view2/${event.id}$`));
    await expect(main(page)).toContainText(/Publication\s*Unpublished/);
  });
  await expectScreen(eventSummary(page), 'event-publish-unpublish.png');
});

test('Event publish – empty event', async ({ page, api, ts, cleanup }) => {
  const info = `QA publish empty ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));

  await page.goto('/events/index');
  await page.getByRole('link', { name: 'Add Event' }).click();
  await dialog(page).getByRole('textbox', { name: /Event Info/ }).fill(info);
  await dialog(page).getByRole('button', { name: 'Create Event Entry' }).click();
  await expect(page.getByRole('heading', { name: info, level: 1 })).toBeVisible();
  await page.getByRole('link', { name: 'Publish Event' }).click();
  await dialog(page).getByRole('button', { name: 'Publish', exact: true }).click();

  // Published, or a clear warning that the event is empty: never an error page.
  await expectNoErrorPage(page);
  await expect(page.getByText(/Job queued|empty|no attribute/i).first()).toBeVisible();
  await expectScreen(eventSummary(page), 'event-publish-empty.png');
});

test('Event delete', async ({ page, api, ts, cleanup }) => {
  const event = await api.createEvent({ info: `QA delete ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  await page.getByRole('link', { name: 'Delete Event' }).click();
  await dialog(page).getByRole('button', { name: /^Delete/ }).click();
  await page.goto('/events/index');

  await expect(row(main(page), event.info)).toHaveCount(0);
  expect(await api.findEvents(event.info)).toHaveLength(0);
  await expectScreen(main(page).getByRole('heading', { name: 'Events', level: 1 }), 'event-delete.png');
});

test('Event delete – event extended by another', async ({ page, api, ts, cleanup }) => {
  const parent = await api.createEvent({ info: `QA parent ${ts}` });
  cleanup(() => api.deleteEventsByInfo(parent.info));
  const childInfo = `QA child ${ts}`;
  cleanup(() => api.deleteEventsByInfo(childInfo));

  await page.goto('/events/index');
  await page.getByRole('link', { name: 'Add Event' }).click();
  await dialog(page).getByRole('textbox', { name: /Event Info/ }).fill(childInfo);
  await dialog(page).getByRole('textbox', { name: 'Extends' }).fill(parent.id);
  await dialog(page).getByRole('button', { name: 'Create Event Entry' }).click();
  await expect(page.getByRole('heading', { name: childInfo, level: 1 })).toBeVisible();
  const childUrl = page.url();

  await openEvent(page, parent.id);
  await page.getByRole('link', { name: 'Delete Event' }).click();
  await dialog(page).getByRole('button', { name: /^Delete/ }).click();
  await page.goto(childUrl);

  await expect(page.getByRole('heading', { name: childInfo, level: 1 })).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(eventSummary(page), 'event-delete-extended.png');
});

test('Event tags and galaxy clusters', async ({ page, api, ts, cleanup }) => {
  const event = await api.createEvent({ info: `QA tags ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  await pick(dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first(), 'tlp:green');
  await dialog(page).getByRole('button', { name: 'Save Tags' }).click();
  await page.getByRole('button', { name: 'Edit Galaxy Clusters' }).click();
  await pick(dialog(page).getByRole('combobox', { name: 'Search clusters to add…' }).first(),
    'Phishing - T1566', /^Phishing - T1566 /);
  await dialog(page).getByRole('button', { name: /^Save/ }).click();
  await expect(eventCard(page, 'tags').getByText('tlp:green')).toBeVisible();
  await expect(eventCard(page, 'galaxy').getByText('Phishing - T1566').first()).toBeVisible();

  // Overmind removes them from the Edit windows: "Remove" next to the item, then save.
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  await dialog(page).getByRole('button', { name: 'Remove' }).first().click();
  await dialog(page).getByRole('button', { name: 'Save Tags' }).click();
  await expect(eventCard(page, 'tags').getByText('tlp:green')).toHaveCount(0);
  await page.getByRole('button', { name: 'Edit Galaxy Clusters' }).click();
  await dialog(page).getByRole('button', { name: 'Remove' }).first().click();
  await dialog(page).getByRole('button', { name: /^Save/ }).click();
  await expect(eventCard(page, 'galaxy').getByText('Phishing - T1566')).toHaveCount(0);

  await expectNoErrorPage(page);
  const saved = await api.getEvent(event.id);
  expect(saved.Tag || []).toHaveLength(0);
  expect(saved.Galaxy || []).toHaveLength(0);
  await expectScreen(eventCard(page, 'tags'), 'event-tags-removed.png');
  await expectScreen(eventCard(page, 'galaxy'), 'event-galaxies-removed.png');
});

test('Event view – event that does not exist', async ({ page }) => {
  await page.goto('/events/view2/999999');

  await expect(page.getByText('Invalid event').first()).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(main(page), 'event-view-not-found.png');
});

test('Event view – open by UUID', async ({ page, api, ts, cleanup }) => {
  const event = await api.createEvent({ info: `QA view by UUID ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  await expect(eventSummary(page)).toContainText(event.uuid);
  await page.goto(`/events/view2/${event.uuid}`);

  await expect(page.getByRole('heading', { name: event.info, level: 1 })).toBeVisible();
  await expect(eventSummary(page)).toContainText(`#${event.id}`);
  await expectScreen(eventSummary(page), 'event-view-uuid.png');
});

test('Event extends – two events extending each other', async ({ page, api, ts, cleanup }) => {
  const a = await api.createEvent({ info: `QA cycle A ${ts}` });
  cleanup(() => api.deleteEventsByInfo(a.info));
  const b = await api.createEvent({ info: `QA cycle B ${ts}` });
  cleanup(() => api.deleteEventsByInfo(b.info));
  await api.post(`/events/edit/${b.id}`, { Event: { extends_uuid: a.uuid } });

  await openEvent(page, a.id);
  await page.getByRole('link', { name: 'Edit Event' }).click();
  await dialog(page).getByRole('textbox', { name: 'Extends' }).fill(b.id);
  await dialog(page).getByRole('button', { name: 'Save Changes' }).click();
  await expectNoErrorPage(page);

  // Refused with a clear message, or both pages open without loop or error.
  for (const event of [a, b]) {
    await openEvent(page, event.id);
    await expect(page.getByRole('heading', { name: event.info, level: 1 })).toBeVisible();
    await expectNoErrorPage(page);
  }
  await expectScreen(eventSummary(page), 'event-extends-cycle.png');
});
