// ../../sharing-group/index/sharing-groups.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, pick, row, dialog,
} = require('../helpers');

const main = (page) => page.getByRole('main');

test.describe('as site admin', () => {
  test.use({ role: 'siteAdmin' });

  test('Sharing group – create with two organisations', async ({ page, api, ts, cleanup }) => {
    const name = `QA SG org A and B ${ts}`;
    cleanup(() => api.deleteSharingGroupByName(name));

    await page.goto('/sharing_groups/index');
    await page.getByRole('link', { name: 'Add SharingGroups' }).click();
    const form = dialog(page);
    await form.getByRole('textbox', { name: 'e.g. Multinational sharing group' }).fill(name);
    await form.getByRole('textbox', { name: /e\.g\. Community1/ }).fill('QA');
    await form.getByRole('button', { name: '2 Organisations' }).click();
    await pick(form.getByRole('combobox', { name: 'Search local organisations…' }), 'QA-Org-B');
    await form.getByRole('button', { name: 'Add Sharing Group' }).click();

    await expect.poll(() => api.findSharingGroup(name)).toBeTruthy();
    await page.goto('/sharing_groups/index');
    await expect(row(main(page), name)).toBeVisible();
    await expectScreen(row(main(page), name), 'sg-create.png', { hide: [ts] });
    await page.goto('/events/index');
    await page.getByRole('link', { name: 'Add Event' }).click();
    await dialog(page).getByRole('radio', { name: /^Sharing group/ }).check();
    const options = await dialog(page).locator('select[name*="sharing_group_id"] option').allTextContents();
    expect(options.map((o) => o.trim())).toContain(name);
  });

  test('Sharing group – emoji in the name', async ({ page, api, ts, cleanup }) => {
    blockedBy('Bug 5 (an emoji in a sharing group name gives "An Internal Error Has Occurred.")');
    const name = `QA SG 🚀 ${ts}`;
    cleanup(() => api.deleteSharingGroupByName(name));

    await page.goto('/sharing_groups/index');
    await page.getByRole('link', { name: 'Add SharingGroups' }).click();
    await dialog(page).getByRole('textbox', { name: 'e.g. Multinational sharing group' }).fill(name);
    await dialog(page).getByRole('button', { name: 'Add Sharing Group' }).click();

    await expectNoErrorPage(page);
    await expect.poll(() => api.findSharingGroup(name)).toBeTruthy();
  });

  test('Sharing group – delete while used', async ({ page, api, ts, cleanup }) => {
    blockedBy('New bug: deleting a sharing group used by an event is refused with only "SharingGroup '
      + 'was not deleted." – the reason is not given');
    const sg = await api.createSharingGroup(`QA SG org A only ${ts}`, ['ADMIN']);
    cleanup(() => api.deleteSharingGroupByName(sg.name));
    const event = await api.createEvent({ info: `QA SG event org A only ${ts}`, distribution: 'sharingGroup', sharingGroupId: sg.id });
    cleanup(() => api.deleteEventsByInfo(event.info));

    await page.goto(`/sharing_groups/view/${sg.id}`);
    await page.getByRole('link', { name: 'Delete SharingGroup' }).click();
    await dialog(page).getByRole('button', { name: /^Delete/ }).click();

    await expectNoErrorPage(page);
    expect(await api.findSharingGroup(sg.name), 'the sharing group is kept').toBeTruthy();
    await expect(page.getByText('SharingGroup was not deleted.')).toBeVisible();
    const message = page.getByText(/used by|still used|events? use/i).filter({ visible: true }).first();
    await expect(message, 'a message that says the sharing group is still used').toBeVisible();
    await expectScreen(message, 'sg-delete-used.png', { hide: [ts] });
  });
});

test.describe('as user of QA-Org-B', () => {
  test.use({ role: 'userB' });

  test('Sharing group – member cannot edit it', async ({ page, api, ts, cleanup }) => {
    const sg = await api.createSharingGroup(`QA SG org A and B ${ts}`, ['ADMIN', 'QA-Org-B']);
    cleanup(() => api.deleteSharingGroupByName(sg.name));

    await page.goto(`/sharing_groups/view/${sg.id}`);
    await expect(page.getByRole('heading', { name: sg.name, level: 1 })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Edit SharingGroup' })).toHaveCount(0);
    await page.goto(`/sharing_groups/edit/${sg.id}`);

    await expect(page.getByText('You do not have permission to use this functionality.').first()).toBeVisible();
    await expectScreen(main(page), 'sg-edit-other-org.png');
  });
});
