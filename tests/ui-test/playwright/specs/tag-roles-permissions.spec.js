// ../../tag/roles/permissions.md
const {
  test, expect, expectScreen, blockedBy, dialog, openEvent, eventCard,
} = require('../helpers');

const main = (page) => page.getByRole('main');

test.describe('as user of QA-Org-B', () => {
  test.use({ role: 'userB' });

  test('Global tag on another organisation\'s event', async ({ page, api, ts, cleanup }) => {
    const event = await api.createEvent({ info: `QA roles community event ${ts}`, distribution: 'community' });
    cleanup(() => api.deleteEventsByInfo(event.info));

    await openEvent(page, event.id);
    // Overmind does not offer Edit Tags on the event of another organisation.
    await expect(page.getByRole('button', { name: 'Edit Tags' })).toHaveCount(0);
    expect((await api.getEvent(event.id)).Tag || []).toHaveLength(0);
    await expectScreen(eventCard(page, 'tags'), 'tag-roles-global-other-org.png');
  });

  test('Local tag on another organisation\'s event', async ({ page, api, ts, cleanup }) => {
    blockedBy('Missing feature: no way to add a local tag on the event of another organisation '
      + '(no Edit Tags button), and no message says why');
    const event = await api.createEvent({ info: `QA roles community event ${ts}`, distribution: 'community' });
    cleanup(() => api.deleteEventsByInfo(event.info));

    await openEvent(page, event.id);
    await expect(page.getByRole('button', { name: 'Edit Tags' }), 'a way to add a local tag')
      .toBeVisible({ timeout: 5_000 });
  });

  test('Tag restricted to an organisation', async ({ page, pageAs, api, apiAs, ts, cleanup }) => {
    const tag = `qa:org-a-only-${ts}`;
    const admin = await api.findOrg('ADMIN');
    await api.post('/tags/add', { Tag: { name: tag, colour: '#7c3aed', org_id: admin.id } });
    cleanup(() => api.deleteTag(tag));
    const ownB = await apiAs('userB').createEvent({ info: `QA restricted tag ${ts}` });
    cleanup(() => api.deleteEventsByInfo(ownB.info));
    const ownA = await apiAs('userA').createEvent({ info: `QA roles org only event ${ts}` });
    cleanup(() => api.deleteEventsByInfo(ownA.info));

    const offered = async (p, eventId) => {
      await openEvent(p, eventId);
      await p.getByRole('button', { name: 'Edit Tags' }).click();
      await dialog(p).getByRole('combobox', { name: 'Search tags to add…' }).first().click();
      await p.keyboard.type(tag);
      await p.waitForTimeout(1_000);
      return p.getByRole('option', { name: tag }).filter({ visible: true }).count();
    };
    expect(await offered(page, ownB.id), 'offered to QA-Org-B').toBe(0);
    await expectScreen(dialog(page), 'tag-roles-restricted-org.png', { hide: [ts] });
    expect(await offered(await pageAs('userA'), ownA.id), 'offered to ADMIN').toBe(1);
  });
});

test.describe('as user of ADMIN', () => {
  test.use({ role: 'userA' });

  test('Tag create – User role', async ({ page }) => {
    await page.goto('/tags/index');
    await expect(page.getByRole('link', { name: /^Add Tag/ })).toHaveCount(0);
    await page.goto('/tags/add');

    await expect(page.getByText('You do not have permission to use this functionality.').first()).toBeVisible();
    await expectScreen(main(page), 'tag-roles-create-user.png');
  });
});
