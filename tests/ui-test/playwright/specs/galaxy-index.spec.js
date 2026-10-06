// ../../galaxy/index/galaxies.md
const {
  test, expect, expectNoErrorPage, expectScreen, blockedBy, pick, row, rowAction, dialog, openEvent, eventCard,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const main = (page) => page.getByRole('main');
const UNPUBLISHED = 'To confirm: a custom cluster is only offered in Edit Galaxy Clusters once it is published';

async function openAddGalaxy(page) {
  await page.goto('/galaxies/index');
  await page.getByRole('link', { name: 'Add Custom Galaxy' }).click();
  return dialog(page);
}

async function searchGalaxies(page, name) {
  await page.goto('/galaxies/index');
  const box = page.getByRole('textbox', { name: 'Search by galaxy name' });
  await box.fill(name);
  await box.press('Enter');
  return row(main(page), name);
}

async function openImport(page) {
  await page.goto('/galaxies/index');
  await page.getByRole('button', { name: 'More actions' }).nth(1).click();
  await page.locator('.dropdown-menu.show').getByRole('link', { name: 'Import Galaxy Clusters' }).click();
  return dialog(page);
}

// The form is refused with `message` (and stays open).
async function expectRefused(form, message) {
  await Promise.race([form.getByText(message).first().waitFor(), form.waitFor({ state: 'hidden' })]);
  expect(await form.isVisible(), 'MISP closed the form without the reason').toBe(true);
  await expect(form.getByText(message).first()).toBeVisible();
}

test('Custom galaxy – empty name', async ({ page }) => {
  const form = await openAddGalaxy(page);
  await form.getByRole('textbox', { name: 'Namespace' }).fill('qa');
  await form.getByRole('button', { name: 'Add Galaxy' }).click();

  await expectRefused(form, 'Please provide a name for the galaxy.');
  await expectScreen(form, 'galaxy-add-empty-name.png');
});

test('Custom galaxy – create', async ({ page, api, ts, cleanup }) => {
  const name = `QA galaxy ${ts}`;
  cleanup(() => api.deleteGalaxyByName(name));

  const form = await openAddGalaxy(page);
  await form.getByRole('textbox', { name: 'Name', exact: true }).fill(name);
  await form.getByRole('textbox', { name: 'Namespace' }).fill('qa');
  await form.getByRole('button', { name: 'Add Galaxy' }).click();

  const r = await searchGalaxies(page, name);
  await expect(r.getByRole('cell', { name: 'Enabled', exact: true })).toBeVisible();
  const galaxy = await api.findGalaxy(name);
  expect(galaxy.default, 'not a default galaxy').toBe(false);
  await expectScreen(r, 'galaxy-add.png', { hide: [ts] });
});

test('Custom galaxy – invalid kill chain order', async ({ page, api, ts, cleanup }) => {
  const name = `QA galaxy kill chain ${ts}`;
  cleanup(() => api.deleteGalaxyByName(name));

  const form = await openAddGalaxy(page);
  await form.getByRole('textbox', { name: 'Name', exact: true }).fill(name);
  await form.getByRole('textbox', { name: 'Namespace' }).fill('qa');
  await form.getByRole('textbox', { name: 'Kill Chain order (for the Galaxy Matrix)' }).fill('not json {');
  await form.getByRole('button', { name: 'Add Galaxy' }).click();
  await Promise.race([form.getByText(/kill chain/i).first().waitFor(), form.waitFor({ state: 'hidden' })]);

  // Refused with a message about the kill chain, or created without it: never an error page.
  await expectNoErrorPage(page);
  const galaxy = await api.findGalaxy(name);
  if (galaxy) expect(galaxy.kill_chain_order).toBeFalsy();
  else await expect(form.getByText(/kill chain/i).first()).toBeVisible();
  await expectScreen(galaxy ? await searchGalaxies(page, name) : form, 'galaxy-add-invalid-kill-chain.png',
    { hide: [ts] });
});

test('Galaxy disable – clusters not offered', async ({ page, api, ts, cleanup }) => {
  blockedBy('New bug: the clusters of a disabled galaxy are still offered in Edit Galaxy Clusters');
  const galaxy = await api.findGalaxy('Threat Actor');
  expect(galaxy.enabled, 'test data: Threat Actor is enabled').toBe(true);
  cleanup(() => api.post(`/galaxies/enable/${galaxy.id}`));
  const event = await api.createEvent({ info: `QA galaxy disabled ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await rowAction(await searchGalaxies(page, 'Threat Actor'), 'Disable');
  await dialog(page).getByRole('button', { name: 'Disable', exact: true }).click();
  await expect.poll(async () => (await api.findGalaxy('Threat Actor')).enabled).toBe(false);

  await openEvent(page, event.id);
  await page.getByRole('button', { name: 'Edit Galaxy Clusters' }).click();
  await dialog(page).getByRole('combobox', { name: 'Search clusters to add…' }).first().click();
  await page.keyboard.type('APT28');
  await expect(page.getByRole('option', { name: /^APT28 - G0007/ }).first()).toBeVisible();
  await expect(page.getByRole('option', { name: /^APT28 Threat Actor$/ })).toHaveCount(0);
  await expectScreen(dialog(page), 'galaxy-disable.png');
});

test('Custom galaxy – delete while used on an event', async ({ page, api, ts, cleanup }) => {
  blockedBy(UNPUBLISHED);
  const galaxy = await api.createGalaxy(`QA galaxy ${ts}`);
  cleanup(() => api.deleteGalaxyByName(galaxy.name));
  const cluster = await api.createCluster(galaxy.id, `QA cluster used ${ts}`);
  const event = await api.createEvent({ info: `QA galaxy delete ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));

  await openEvent(page, event.id);
  await page.getByRole('button', { name: 'Edit Galaxy Clusters' }).click();
  await pick(dialog(page).getByRole('combobox', { name: 'Search clusters to add…' }).first(), cluster.value);
  await dialog(page).getByRole('button', { name: /^Save/ }).click();
  await expect(eventCard(page, 'galaxy').getByText(cluster.value)).toBeVisible();

  await rowAction(await searchGalaxies(page, galaxy.name), 'Delete');
  await dialog(page).getByRole('button', { name: /^Delete/ }).click();
  await expect.poll(() => api.findGalaxy(galaxy.name)).toBeUndefined();

  await openEvent(page, event.id);
  await expectNoErrorPage(page);
  await expectScreen(eventCard(page, 'galaxy'), 'galaxy-delete-used.png', { hide: [ts] });
});

test('Galaxy import – invalid JSON', async ({ page }) => {
  const form = await openImport(page);
  await form.getByRole('textbox', { name: 'Galaxy Clusters JSON' }).fill('{ not json');
  await form.getByRole('button', { name: 'Import' }).click();

  await expectNoErrorPage(page);
  await expectRefused(form, /JSON/i);
  await expectScreen(form, 'galaxy-import-invalid-json.png');
});

test('Galaxy import – JSON without cluster', async ({ page }) => {
  const form = await openImport(page);
  await form.getByRole('textbox', { name: 'Galaxy Clusters JSON' }).fill('[{"Galaxy": {"name": "QA"}}]');
  await form.getByRole('button', { name: 'Import' }).click();

  await expectNoErrorPage(page);
  const message = page.getByText(/0 imported.*holds no galaxy cluster.*"GalaxyCluster"/).first();
  await expect(message).toBeVisible();
  await expectScreen(message, 'galaxy-import-no-cluster.png');
});
