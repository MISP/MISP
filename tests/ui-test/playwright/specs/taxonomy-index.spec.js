// ../../taxonomy/index/actions.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, pick, row, rowAction, dialog,
  openEvent, openTab, eventCard, offeredTags, expectAfterReload, taxonomyRow, taxonomyAction,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const main = (page) => page.getByRole('main');
const ADMIRALTY_A = 'admiralty-scale:source-reliability="a"';

async function publish(page, notify) {
  await page.getByRole('link', { name: 'Publish Event' }).click();
  const form = dialog(page);
  if (notify) await form.getByRole('switch', { name: 'Send notification email' }).check();
  await form.getByRole('button', { name: /^Publish/ }).click();
}

test('Taxonomy enable and disable', async ({ page, api, ts, cleanup }) => {
  blockedBy('To confirm: enabling a taxonomy does not make its tags available – Disable hides them, '
    + 'Enable does not show them again (only "Enable all tags" does)');
  cleanup(await api.keepTaxonomyState('PAP'));
  const event = await api.createEvent({ info: `QA taxonomy toggle ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await taxonomyAction(page, 'PAP', 'Enable');
  await expect.poll(async () => (await api.findTaxonomy('PAP')).enabled).toBe(true);
  expect((await offeredTags(page, event.id, 'PAP:')).some((n) => n.startsWith('PAP:')),
    'PAP: tags offered once the taxonomy is enabled').toBe(true);

  await taxonomyAction(page, 'PAP', 'Disable');
  await expect.poll(async () => (await api.findTaxonomy('PAP')).enabled).toBe(false);
  expect((await offeredTags(page, event.id, 'PAP:')).filter((n) => n.startsWith('PAP:'))).toEqual([]);
  await expectScreen(await taxonomyRow(page, 'PAP'), 'taxonomy-enable-disable.png');
});

for (const notify of [false, true]) {
  test(`Taxonomy required – publish ${notify ? 'with' : 'without'} notification`, async ({
    page, api, ts, cleanup,
  }) => {
    cleanup(await api.keepTaxonomyState('tlp'));
    const event = await api.createEvent({ info: `QA required tlp${notify ? ' email' : ''} ${ts}` });
    cleanup(() => api.deleteEventsByInfo(event.info));

    await taxonomyAction(page, 'tlp', 'Require');
    await expect.poll(async () => (await api.findTaxonomy('tlp')).required).toBe(true);
    await openEvent(page, event.id);
    await publish(page, notify);

    await expect(page.getByText('Could not publish event - no tag for required taxonomies missing: tlp').first())
      .toBeVisible();
    expect((await api.getEvent(event.id)).published).toBe(false);
    await expectScreen(page.getByText(/no tag for required taxonomies missing/).first(),
      `taxonomy-required-publish-${notify ? 'email' : 'no-email'}.png`);
  });
}

test('Taxonomy required – publish with the required tag', async ({ page, api, ts, cleanup }) => {
  cleanup(await api.keepTaxonomyState('tlp'));
  const event = await api.createEvent({ info: `QA required tlp tagged ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await taxonomyAction(page, 'tlp', 'Require');
  await expect.poll(async () => (await api.findTaxonomy('tlp')).required).toBe(true);
  await openEvent(page, event.id);
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  await pick(dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first(), 'tlp:green');
  await dialog(page).getByRole('button', { name: 'Save Tags' }).click();
  await publish(page, false);

  await expectNoErrorPage(page);
  await expect.poll(async () => (await api.getEvent(event.id)).published).toBe(true);
  await expectAfterReload(page, () => expect(main(page)).toContainText(/Publication\s*Published/));
  await expectScreen(eventCard(page, 'tags'), 'taxonomy-required-publish-tagged.png');
});

test('Taxonomy disabled – tag already on an event', async ({ page, api, ts, cleanup }) => {
  cleanup(await api.keepTaxonomyState('admiralty-scale'));
  cleanup(await api.enableTaxonomy('admiralty-scale'));
  cleanup(await api.showTag(ADMIRALTY_A));
  const event = await api.createEvent({ info: `QA disabled taxonomy ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  await page.getByRole('button', { name: 'Edit Tags' }).click();
  await pick(dialog(page).getByRole('combobox', { name: 'Search tags to add…' }).first(), ADMIRALTY_A);
  await dialog(page).getByRole('button', { name: 'Save Tags' }).click();
  await expect(eventCard(page, 'tags').getByText(ADMIRALTY_A)).toBeVisible();

  await taxonomyAction(page, 'admiralty-scale', 'Disable');
  await expect.poll(async () => (await api.findTaxonomy('admiralty-scale')).enabled).toBe(false);
  await openEvent(page, event.id);
  await expectNoErrorPage(page);
  await expect(eventCard(page, 'tags').getByText(ADMIRALTY_A)).toBeVisible();
  await expectScreen(eventCard(page, 'tags'), 'taxonomy-disabled-tag-on-event.png');
});

test('Taxonomy update', async ({ page, api }) => {
  test.setTimeout(240_000);
  const enabled = async () => (await api.get('/taxonomies/index')).map((t) => t.Taxonomy)
    .filter((t) => t.enabled).map((t) => t.namespace).sort();
  const before = await enabled();
  const count = (await api.get('/taxonomies/index')).length;

  await page.goto('/taxonomies/index');
  await page.getByRole('link', { name: 'Update Taxonomies' }).click();
  const confirm = dialog(page).getByRole('button', { name: /Update/ });
  if (await confirm.isVisible().catch(() => false)) await confirm.click();
  await expect(page.getByText(/up to date|updated|success/i).first()).toBeVisible({ timeout: 180_000 });
  await page.reload();

  await expectNoErrorPage(page);
  expect((await api.get('/taxonomies/index')).length).toBeGreaterThanOrEqual(count);
  expect(await enabled()).toEqual(before);
  await expectScreen(main(page).getByRole('heading', { name: 'Taxonomies', level: 1 }), 'taxonomy-update.png');
});

test('Taxonomy and galaxy disabled – tags on event, attribute and object', async ({
  page, api, ts, cleanup,
}) => {
  blockedBy('New bug: the clusters of a disabled galaxy are still offered in Edit Galaxy Clusters');
  cleanup(await api.keepTaxonomyState('admiralty-scale'));
  cleanup(await api.enableTaxonomy('admiralty-scale'));
  cleanup(await api.showTag(ADMIRALTY_A));
  const threatActor = await api.findGalaxy('Threat Actor');
  cleanup(() => api.post(`/galaxies/enable/${threatActor.id}`));
  const apt28 = 'misp-galaxy:threat-actor="APT28"';
  const event = await api.createEvent({
    info: `QA disable taxonomy and galaxy ${ts}`,
    tags: [ADMIRALTY_A, apt28],
    attributes: [{ type: 'ip-dst', category: 'Network activity', value: '198.51.100.130' }],
    objects: [{ name: 'domain-ip', attributes: [{ object_relation: 'domain', type: 'domain', value: 'qa-disable.example' }] }],
  });
  cleanup(() => api.deleteEventsByInfo(event.info));
  const full = await api.getEvent(event.id);
  for (const uuid of [full.Attribute[0].uuid, full.Object[0].Attribute[0].uuid]) {
    for (const tag of [ADMIRALTY_A, apt28]) await api.post('/tags/attachTagToObject', { uuid, tag });
  }

  await taxonomyAction(page, 'admiralty-scale', 'Disable');
  await page.goto('/galaxies/index');
  const galaxySearch = page.getByRole('textbox', { name: 'Search by galaxy name' });
  await galaxySearch.fill('Threat Actor');
  await galaxySearch.press('Enter');
  await rowAction(row(main(page), 'Threat Actor'), 'Disable');
  await dialog(page).getByRole('button', { name: 'Disable', exact: true }).click();
  await expect.poll(async () => (await api.findGalaxy('Threat Actor')).enabled).toBe(false);

  await openEvent(page, event.id);
  await expectNoErrorPage(page);
  await expect(eventCard(page, 'tags').getByText(ADMIRALTY_A)).toBeVisible();
  await expect(eventCard(page, 'galaxy').getByText('APT28').first()).toBeVisible();
  const attributes = await openTab(page, 'Attributes');
  await expect(row(attributes, '198.51.100.130')).toContainText(ADMIRALTY_A);
  await expect(row(attributes, '198.51.100.130')).toContainText('APT28');

  const offered = await offeredTags(page, event.id, 'admiralty-scale:');
  expect(offered.filter((n) => n.startsWith('admiralty-scale:'))).toEqual([]);
  await openEvent(page, event.id);
  await page.getByRole('button', { name: 'Edit Galaxy Clusters' }).click();
  await dialog(page).getByRole('combobox', { name: 'Search clusters to add…' }).first().click();
  await page.keyboard.type('APT29');
  await page.waitForTimeout(1_500);
  await expect(page.getByRole('option', { name: /^APT29 Threat Actor$/ })).toHaveCount(0);
  await expectScreen(eventCard(page, 'galaxy'), 'taxonomy-galaxy-disabled-everywhere.png');
});
