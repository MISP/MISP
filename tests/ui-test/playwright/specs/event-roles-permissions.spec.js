// ../../event/roles/permissions.md
const {
  test, expect, expectNoErrorPage, expectScreen, openEvent, openTab, row, dialog,
  eventSummary, expectAfterReload,
} = require('../helpers');

const ip = { type: 'ip-dst', category: 'Network activity', value: '203.0.113.120' };
const main = (page) => page.getByRole('main');

test.describe('as user of QA-Org-B', () => {
  test.use({ role: 'userB' });

  test('Event visibility – organisation-only event', async ({ page, api, ts, cleanup }) => {
    const event = await api.createEvent({ info: `QA roles org only event ${ts}`, distribution: 'org' });
    cleanup(() => api.deleteEventsByInfo(event.info));

    await page.goto('/events/index');
    const search = page.getByRole('textbox', { name: 'Search by info, ID or UUID' });
    await search.fill(event.info);
    await search.press('Enter');
    await expect(row(main(page), event.info)).toHaveCount(0);

    await page.goto(`/events/view2/${event.id}`);
    await expect(page.getByText('Invalid event').first()).toBeVisible();
    await expect(page.getByText(event.info)).toHaveCount(0);
    await expectScreen(main(page), 'event-roles-org-only-hidden.png');
  });

  test('Event visibility – community event', async ({ page, api, ts, cleanup }) => {
    const event = await api.createEvent({
      info: `QA roles community event ${ts}`, distribution: 'community', attributes: [ip],
    });
    cleanup(() => api.deleteEventsByInfo(event.info));

    await page.goto('/events/index');
    await row(main(page), event.info).getByRole('link', { name: `#${event.id}` }).click();

    await expect(page.getByRole('heading', { name: event.info, level: 1 })).toBeVisible();
    const attributes = await openTab(page, 'Attributes');
    await expect(row(attributes, ip.value)).toBeVisible();
    await expectNoErrorPage(page);
    await expectScreen(row(attributes, ip.value), 'event-roles-community-visible.png');
  });

  test('Event edit – other organisation', async ({ page, api, ts, cleanup }) => {
    const event = await api.createEvent({
      info: `QA roles community event ${ts}`, distribution: 'community', attributes: [ip],
    });
    cleanup(() => api.deleteEventsByInfo(event.info));

    await openEvent(page, event.id);
    await expect(page.getByRole('link', { name: 'Edit Event' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Add Attribute' })).toHaveCount(0);
    const attributes = await openTab(page, 'Attributes');
    await row(attributes, ip.value).getByRole('button').last().click();
    const menu = page.locator('.dropdown-menu.show');
    await expect(menu.getByRole('link', { name: 'Delete', exact: true })).toHaveCount(0);
    await expect(menu.getByRole('link', { name: 'Edit', exact: true })).toHaveCount(0);
    await page.keyboard.press('Escape');

    await page.goto(`/events/edit/${event.id}`);
    await expect(page.getByText('You are not authorised to do that.').first()).toBeVisible();
    expect((await api.getEvent(event.id)).info).toBe(event.info);
    await expectScreen(main(page), 'event-roles-edit-other-org.png');
  });
});

test.describe('as user of ADMIN', () => {
  test.use({ role: 'userA' });

  test('Event edit – same organisation, other user', async ({ page, api, ts, cleanup }) => {
    const event = await api.createEvent({ info: `QA roles org only event ${ts}`, distribution: 'org' });
    const edited = `QA roles org only event – edited ${ts}`;
    cleanup(() => api.deleteEventsByInfo(event.info));
    cleanup(() => api.deleteEventsByInfo(edited));

    await openEvent(page, event.id);
    await page.getByRole('link', { name: 'Edit Event' }).click();
    await dialog(page).getByRole('textbox', { name: /Event Info/ }).fill(edited);
    await dialog(page).getByRole('button', { name: 'Save Changes' }).click();

    await expect(page.getByRole('heading', { name: edited, level: 1 })).toBeVisible();
    expect((await api.getEvent(event.id)).info).toBe(edited);
    await expectScreen(eventSummary(page), 'event-roles-edit-same-org.png');
  });

  test('Event publish – User role', async ({ page, api, ts, cleanup }) => {
    const event = await api.createEvent({ info: `QA roles org only event ${ts}`, distribution: 'org' });
    cleanup(() => api.deleteEventsByInfo(event.info));

    await openEvent(page, event.id);
    const publish = page.getByRole('link', { name: 'Publish Event' });
    if (await publish.count()) {
      await publish.click();
      await dialog(page).getByRole('button', { name: 'Publish', exact: true }).click();
      await expect(page.getByText('You do not have permission to use this functionality.').first())
        .toBeVisible();
    }
    expect((await api.getEvent(event.id)).published).toBe(false);
    await expectScreen(eventSummary(page), 'event-roles-publish-user.png');
  });
});

test.describe('as org-admin of ADMIN', () => {
  test.use({ role: 'orgAdminA' });

  test('Event publish – Org Admin role', async ({ page, api, ts, cleanup }) => {
    const event = await api.createEvent({ info: `QA roles org only event ${ts}`, distribution: 'org' });
    cleanup(() => api.deleteEventsByInfo(event.info));

    await openEvent(page, event.id);
    await page.getByRole('link', { name: 'Publish Event' }).click();
    await dialog(page).getByRole('button', { name: 'Publish', exact: true }).click();
    await expect(page.getByText('Job queued')).toBeVisible();

    await expectAfterReload(page, () => expect(main(page)).toContainText(/Publication\s*Published/));
    await expectScreen(eventSummary(page), 'event-roles-publish-org-admin.png');
  });
});
