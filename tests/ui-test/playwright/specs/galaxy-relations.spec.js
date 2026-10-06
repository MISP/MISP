// ../../galaxy/cluster/relations.md
const {
  test, expect, expectNoErrorPage, expectServerOk, blockedBy, expectScreen, pick, dialog,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

// Overmind adds cluster relations from /galaxy_cluster_relations/index, by UUID.
async function addRelation(page, source, target, type) {
  await page.goto('/galaxy_cluster_relations/index');
  await page.getByRole('link', { name: 'Add relationship' }).click();
  const form = dialog(page);
  await form.getByRole('textbox', { name: 'UUID of the cluster the relationship starts from' }).fill(source.uuid);
  await form.getByRole('textbox', { name: 'UUID of the cluster the relationship points to' }).fill(target.uuid);
  if (type) await pick(form.getByRole('combobox', { name: 'e.g. is-similar' }), type);
  await form.getByRole('button', { name: 'Add Relationship' }).click();
  return form;
}

async function openRelations(page, cluster) {
  await page.goto(`/galaxy_clusters/view/${cluster.id}`);
  await page.getByRole('tab', { name: /^Relations/ }).click();
  return page.getByRole('tabpanel').filter({ visible: true });
}

async function twoClusters(api, cleanup, ts) {
  const galaxy = await api.createGalaxy(`QA galaxy ${ts}`);
  cleanup(() => api.deleteGalaxyByName(galaxy.name));
  return [
    await api.createCluster(galaxy.id, `QA relation source ${ts}`),
    await api.createCluster(galaxy.id, `QA relation target ${ts}`),
  ];
}

test('Cluster relation – between two clusters', async ({ page, api, ts, cleanup }) => {
  const [source, target] = await twoClusters(api, cleanup, ts);
  await addRelation(page, source, target, 'attributed-to');

  const outbound = await openRelations(page, source);
  await expect(outbound).toContainText(/Outbound/i);
  await expect(outbound).toContainText('attributed-to');
  await expect(outbound).toContainText(target.value);
  await expectScreen(outbound, 'galaxy-cluster-relation-outbound.png', { hide: [ts] });
  const inbound = await openRelations(page, target);
  await expect(inbound).toContainText(/Inbound/i);
  await expect(inbound).toContainText(source.value);
});

test('Cluster relation – without type', async ({ page, api, ts, cleanup }) => {
  const [source, target] = await twoClusters(api, cleanup, ts);
  const form = await addRelation(page, source, target, null);

  await Promise.race([form.getByText('A relationship type is required.').waitFor(), form.waitFor({ state: 'hidden' })]);
  expect(await form.isVisible(), 'MISP closed the form without the reason').toBe(true);
  await expect(form.getByText('A relationship type is required.')).toBeVisible();
  await expectScreen(form, 'galaxy-cluster-relation-no-type.png');
});

test('Cluster relation – to itself', async ({ page, api, ts, cleanup }) => {
  const [source] = await twoClusters(api, cleanup, ts);
  const form = await addRelation(page, source, source, 'related-to');
  await Promise.race([form.getByText(/itself|same cluster/i).first().waitFor(), form.waitFor({ state: 'hidden' })]);

  // Refused with a clear message, or created and shown without loop or error.
  await expectNoErrorPage(page);
  if (await form.isVisible()) {
    await expect(form.getByText(/itself|same cluster/i).first()).toBeVisible();
    await expectScreen(form, 'galaxy-cluster-relation-self.png');
  } else {
    const relations = await openRelations(page, source);
    await expectNoErrorPage(page);
    await expectScreen(relations, 'galaxy-cluster-relation-self.png', { hide: [ts] });
  }
});

test('Cluster relation – target deleted', async ({ page, api, ts, cleanup }) => {
  blockedBy('New bug: deleting a cluster is black-holed (HTTP 400, "\'_Token\' was not found in request data")');
  const [source, target] = await twoClusters(api, cleanup, ts);
  await addRelation(page, source, target, 'attributed-to');
  await expect(await openRelations(page, source)).toContainText(target.value);

  await page.goto(`/galaxy_clusters/view/${target.id}`);
  await page.getByRole('link', { name: 'Delete Cluster' }).click();
  await expectServerOk(dialog(page).getByRole('button', { name: 'Soft-delete' }), '/galaxy_clusters/delete/');
  await expect.poll(async () => (await api.getCluster(target.id)).deleted).toBe(true);

  const relations = await openRelations(page, source);
  await expectNoErrorPage(page);
  await expectScreen(relations, 'galaxy-cluster-relation-target-deleted.png', { hide: [ts] });
});
