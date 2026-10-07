// ../../sharing-group/visibility/visibility.md
const {
  test, expect, expectScreen, openEvent, openTab, row, dialog,
} = require('../helpers');

test.use({ role: 'userB' });

const main = (page) => page.getByRole('main');
const ip = (value, extra = {}) => ({ type: 'ip-dst', category: 'Network activity', value, ...extra });

async function groups(api, cleanup, ts) {
  const orgAOnly = await api.createSharingGroup(`QA SG org A only ${ts}`, ['ADMIN']);
  const orgAB = await api.createSharingGroup(`QA SG org A and B ${ts}`, ['ADMIN', 'QA-Org-B']);
  cleanup(() => api.deleteSharingGroupByName(orgAOnly.name));
  cleanup(() => api.deleteSharingGroupByName(orgAB.name));
  return { orgAOnly, orgAB };
}

test('Event in a sharing group – not a member', async ({ page, api, ts, cleanup }) => {
  const { orgAOnly } = await groups(api, cleanup, ts);
  const event = await api.createEvent({ info: `QA SG event org A only ${ts}`, distribution: 'sharingGroup', sharingGroupId: orgAOnly.id });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await page.goto('/events/index');
  const search = page.getByRole('textbox', { name: 'Search by info, ID or UUID' });
  await search.fill(event.info);
  await search.press('Enter');
  await expect(row(main(page), event.info)).toHaveCount(0);
  await page.goto(`/events/view2/${event.id}`);
  await expect(page.getByText('Invalid event').first()).toBeVisible();
  await expectScreen(main(page), 'sg-event-not-member.png');
});

test('Event in a sharing group – member', async ({ page, api, ts, cleanup }) => {
  const { orgAOnly, orgAB } = await groups(api, cleanup, ts);
  const event = await api.createEvent({
    info: `QA SG event org A and B ${ts}`, distribution: 'sharingGroup', sharingGroupId: orgAB.id,
    attributes: [ip('198.51.100.140', { distribution: 4, sharing_group_id: orgAOnly.id }), ip('198.51.100.141')],
  });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  const attributes = await openTab(page, 'Attributes');
  await expect(row(attributes, '198.51.100.141')).toBeVisible();
  await expect(row(attributes, '198.51.100.140')).toHaveCount(0);
  await expectScreen(attributes.getByRole('table'), 'sg-event-member.png');
});

test('Sharing group – not a member cannot use it', async ({ page, api, ts, cleanup }) => {
  const { orgAOnly, orgAB } = await groups(api, cleanup, ts);

  await page.goto('/events/index');
  await page.getByRole('link', { name: 'Add Event' }).click();
  await dialog(page).getByRole('radio', { name: /^Sharing group/ }).check();
  const options = (await dialog(page).locator('select[name*="sharing_group_id"] option').allTextContents())
    .map((o) => o.trim());

  expect(options).toContain(orgAB.name);
  expect(options).not.toContain(orgAOnly.name);
  await expectScreen(dialog(page), 'sg-use-not-member.png', { hide: [ts] });
});

test('Sharing group – organisation removed', async ({ page, pageAs, api, ts, cleanup }) => {
  const { orgAB } = await groups(api, cleanup, ts);
  const event = await api.createEvent({ info: `QA SG event org A and B ${ts}`, distribution: 'sharingGroup', sharingGroupId: orgAB.id });
  cleanup(() => api.deleteEventsByInfo(event.info));

  const admin = await pageAs('siteAdmin');
  await admin.goto(`/sharing_groups/view/${orgAB.id}`);
  await admin.getByRole('link', { name: 'Edit SharingGroup' }).click();
  const form = dialog(admin);
  await form.getByRole('button', { name: '2 Organisations' }).click();
  await form.getByRole('row').filter({ hasText: 'QA-Org-B' }).locator('.sg-org-remove').click();
  await form.getByRole('button', { name: 'Save Changes' }).click();
  await expect.poll(async () => (await api.get(`/sharing_groups/view/${orgAB.id}`)).SharingGroupOrg
    .map((o) => o.Organisation.name)).toEqual(['ADMIN']);

  await page.goto(`/events/view2/${event.id}`);
  await expect(page.getByText('Invalid event').first()).toBeVisible();
  await expectScreen(main(page), 'sg-org-removed.png');
});
