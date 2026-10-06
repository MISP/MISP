// ../../galaxy/cluster/clusters.md
const {
  test, expect, expectNoErrorPage, expectServerOk, blockedBy, expectScreen, pick, dialog, openEvent, eventCard,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const UNPUBLISHED = 'To confirm: a custom cluster is only offered in Edit Galaxy Clusters once it is published';
const main = (page) => page.getByRole('main');

async function newGalaxy(api, cleanup, ts) {
  const galaxy = await api.createGalaxy(`QA galaxy ${ts}`);
  cleanup(() => api.deleteGalaxyByName(galaxy.name));
  return galaxy;
}

async function openAddCluster(page, galaxy) {
  await page.goto(`/galaxies/view/${galaxy.id}`);
  await page.getByRole('link', { name: 'Add Galaxy Cluster' }).click();
  return dialog(page);
}

// Adds the cluster `value` to an event through Edit Galaxy Clusters.
async function attachCluster(page, eventId, value) {
  await openEvent(page, eventId);
  await page.getByRole('button', { name: 'Edit Galaxy Clusters' }).click();
  await pick(dialog(page).getByRole('combobox', { name: 'Search clusters to add…' }).first(), value);
  await dialog(page).getByRole('button', { name: /^Save/ }).click();
  await expect(eventCard(page, 'galaxy').getByText(value)).toBeVisible();
}

test('Cluster add – empty name', async ({ page, api, ts, cleanup }) => {
  const galaxy = await newGalaxy(api, cleanup, ts);
  const form = await openAddCluster(page, galaxy);
  await form.getByRole('button', { name: 'Add Cluster' }).click();

  await Promise.race([form.getByText('A name is required.').waitFor(), form.waitFor({ state: 'hidden' })]);
  expect(await form.isVisible(), 'MISP closed the form without the reason').toBe(true);
  await expect(form.getByText('A name is required.')).toBeVisible();
  await expectScreen(form, 'galaxy-cluster-add-empty-name.png');
});

test('Cluster add – with elements', async ({ page, api, ts, cleanup }) => {
  const galaxy = await newGalaxy(api, cleanup, ts);
  const name = `QA cluster elements ${ts}`;
  const form = await openAddCluster(page, galaxy);
  await form.getByRole('textbox', { name: 'e.g. APT28' }).fill(name);
  await form.getByRole('textbox', { name: 'Cluster Elements' }).fill(JSON.stringify([
    { key: 'country', value: 'LU' }, { key: 'synonyms', value: 'QA alias' },
  ]));
  await form.getByRole('button', { name: 'Add Cluster' }).click();

  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible();
  const elements = page.getByRole('tab', { name: /^Elements/ });
  await expect(elements).toHaveText(/Elements\s*\(2\)/);
  await elements.click();
  const panel = page.getByRole('tabpanel').filter({ visible: true });
  await expect(panel).toContainText('country');
  await expect(panel).toContainText('QA alias');
  await expectScreen(panel, 'galaxy-cluster-add-elements.png');

  await page.goto(`/galaxies/view/${galaxy.id}`);
  await page.getByRole('tab', { name: /^Clusters/ }).click();
  const search = page.getByRole('tabpanel').filter({ visible: true }).getByRole('textbox').first();
  await search.fill('QA alias');
  await search.press('Enter');
  await expect(main(page).getByRole('row').filter({ hasText: name })).toBeVisible();
});

test('Cluster fork – default cluster', async ({ page, api, ts, cleanup }) => {
  const original = await api.findCluster('threat-actor', 'APT28');
  const description = `QA forked cluster ${ts}`;
  cleanup(async () => {
    const { response } = await api.post('/galaxy_clusters/restSearch', { value: 'APT28' });
    for (const { GalaxyCluster: c } of response || []) {
      if (c.description === description) await api.post(`/galaxy_clusters/delete/${c.id}/1`);
    }
  });

  await page.goto(`/galaxy_clusters/view/${original.id}`);
  await page.getByRole('link', { name: 'Fork Cluster' }).click();
  const form = dialog(page);
  await form.getByRole('textbox', { name: 'Briefly describe what this cluster stands for…' }).fill(description);
  await form.getByRole('button', { name: /Fork/ }).last().click();

  await expect(main(page).getByText(description).first()).toBeVisible();
  expect((await api.getCluster(original.id)).description).toBe(original.description);
  await expectScreen(main(page).getByText(description).first(), 'galaxy-cluster-fork.png', { hide: [ts] });
});

test('Cluster rename – used on an event', async ({ page, api, ts, cleanup }) => {
  blockedBy(UNPUBLISHED);
  const galaxy = await newGalaxy(api, cleanup, ts);
  const cluster = await api.createCluster(galaxy.id, `QA cluster old name ${ts}`);
  const newName = `QA cluster new name ${ts}`;
  const event = await api.createEvent({ info: `QA cluster rename ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await attachCluster(page, event.id, cluster.value);
  await page.goto(`/galaxy_clusters/view/${cluster.id}`);
  await page.getByRole('link', { name: 'Edit Cluster' }).click();
  await dialog(page).getByRole('textbox', { name: 'e.g. APT28' }).fill(newName);
  await dialog(page).getByRole('button', { name: /Save/ }).click();

  await openEvent(page, event.id);
  await expect(eventCard(page, 'galaxy').getByText(newName)).toHaveCount(1);
  await expect(eventCard(page, 'galaxy').getByText(cluster.value)).toHaveCount(0);
  await expectScreen(eventCard(page, 'galaxy'), 'galaxy-cluster-rename-used.png', { hide: [ts] });
});

test('Cluster soft-delete and restore – used on an event', async ({ page, api, ts, cleanup }) => {
  blockedBy(UNPUBLISHED);
  const galaxy = await newGalaxy(api, cleanup, ts);
  const cluster = await api.createCluster(galaxy.id, `QA cluster deleted ${ts}`);
  const event = await api.createEvent({ info: `QA cluster soft delete ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await attachCluster(page, event.id, cluster.value);
  await page.goto(`/galaxy_clusters/view/${cluster.id}`);
  await page.getByRole('link', { name: 'Delete Cluster' }).click();
  await dialog(page).getByRole('button', { name: 'Soft-delete' }).click();
  await openEvent(page, event.id);
  await expectNoErrorPage(page);

  await page.goto(`/galaxy_clusters/view/${cluster.id}`);
  await page.getByRole('link', { name: /Restore/ }).click();
  const confirm = dialog(page);
  await confirm.getByRole('button', { name: /Restore/ }).click();
  await expect.poll(async () => (await api.getCluster(cluster.id)).deleted).toBe(false);
  await openEvent(page, event.id);
  await expect(eventCard(page, 'galaxy').getByText(cluster.value)).toBeVisible();
  await expectScreen(eventCard(page, 'galaxy'), 'galaxy-cluster-soft-delete.png', { hide: [ts] });
});

test('Cluster hard-delete – re-import', async ({ page, api, ts, cleanup }, testInfo) => {
  blockedBy('New bug: deleting a cluster is black-holed (HTTP 400, "\'_Token\' was not found in request data")');
  const galaxy = await newGalaxy(api, cleanup, ts);
  const cluster = await api.createCluster(galaxy.id, `QA cluster hard ${ts}`);

  await page.goto(`/galaxies/view/${galaxy.id}`);
  await page.getByRole('link', { name: 'Export Galaxy Clusters' }).click();
  const exportForm = dialog(page);
  await exportForm.getByRole('checkbox', { name: 'Organisation' }).check();
  await exportForm.getByText('To re-import into another MISP').click();
  await exportForm.getByText('Save the JSON as a file').click();
  const pending = page.waitForEvent('download');
  await exportForm.getByRole('button', { name: 'Export' }).click();
  const file = testInfo.outputPath('clusters.json');
  await (await pending).saveAs(file);
  const exported = require('fs').readFileSync(file, 'utf8');
  expect(exported).toContain(cluster.uuid);

  await page.goto(`/galaxy_clusters/view/${cluster.id}`);
  await page.getByRole('link', { name: 'Delete Cluster' }).click();
  await dialog(page).getByRole('checkbox', { name: /^Permanently delete/ }).check();
  await expectServerOk(dialog(page).getByRole('button', { name: 'Hard-delete' }), '/galaxy_clusters/delete/');
  await expect.poll(async () => (await api.get(`/galaxy_clusters/view/${cluster.id}`).catch(() => null))).toBeNull();

  await page.goto('/galaxies/index');
  await page.getByRole('button', { name: 'More actions' }).nth(1).click();
  await page.locator('.dropdown-menu.show').getByRole('link', { name: 'Import Galaxy Clusters' }).click();
  await dialog(page).getByRole('textbox', { name: 'Galaxy Clusters JSON' }).fill(exported);
  await dialog(page).getByRole('button', { name: 'Import' }).click();

  await expect(page.getByText(/blocklist/i).first()).toBeVisible();
  const { response } = await api.post('/galaxy_clusters/restSearch', { uuid: cluster.uuid });
  expect(response || []).toHaveLength(0);
  await expectScreen(page.getByText(/blocklist/i).first(), 'galaxy-cluster-hard-delete-reimport.png');
});

test('Cluster publish', async ({ page, api, ts, cleanup }) => {
  const galaxy = await newGalaxy(api, cleanup, ts);
  const cluster = await api.createCluster(galaxy.id, `QA cluster publish ${ts}`);

  await page.goto(`/galaxy_clusters/view/${cluster.id}`);
  await page.getByRole('link', { name: 'Publish Cluster' }).click();
  await dialog(page).getByRole('button', { name: 'Publish', exact: true }).click();

  await expect.poll(async () => (await api.getCluster(cluster.id)).published).toBe(true);
  await page.reload();
  await expect(main(page).getByText(/Published/).first()).toBeVisible();
  await expectScreen(page.getByRole('tabpanel').filter({ visible: true }), 'galaxy-cluster-publish.png', { hide: [ts] });
});
