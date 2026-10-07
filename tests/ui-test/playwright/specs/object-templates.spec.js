// ../../object/templates/templates.md
const {
  test, expect, expectNoErrorPage, expectDialogSaved, expectScreen, dialog, pick,
  reviewObject, openObjects, objectItem, openEvent,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const TEMPLATE = 'geolocation';

async function templateRow(page, name) {
  await page.goto(`/objectTemplates/index/searchall:${name}`);
  const found = page.getByRole('main').getByRole('row')
    .filter({ has: page.getByText(name, { exact: true }) }).first();
  await expect(found).toBeVisible();
  return found;
}

// Activate / Deactivate in the row menu of the template.
async function setActive(page, name, action) {
  const templateRowFound = await templateRow(page, name);
  await templateRowFound.locator('button').last().click();
  await page.locator('.dropdown-menu.show').getByRole('link', { name: action, exact: true }).click();
  await page.waitForLoadState('load');
  await expectNoErrorPage(page);
}

const isActive = async (api, name) => (await api.objectTemplates()).find((t) => t.name === name).active;

// The templates offered by Add Object for `search`.
async function offeredTemplates(page, eventId, search) {
  await openEvent(page, eventId);
  await page.getByRole('link', { name: 'Add Object' }).click();
  const combobox = dialog(page).getByRole('combobox', { name: /Template/ });
  await combobox.locator('xpath=ancestor::*[contains(@class,"ts-control")][1]').click();
  await page.keyboard.type(search, { delay: 20 });
  const options = page.locator('.ts-dropdown .option').filter({ visible: true });
  await expect(options.first().or(page.locator('.ts-dropdown .no-results').filter({ visible: true })))
    .toBeVisible();
  return options;
}

async function newEvent(api, cleanup, info) {
  cleanup(() => api.deleteEventsByInfo(info));
  return api.createEvent({ info });
}

test('Object template deactivate', async ({ page, api, ts, cleanup }) => {
  cleanup(await api.keepObjectTemplateActive(TEMPLATE));
  const event = await newEvent(api, cleanup, `QA template deactivate ${ts}`);

  await setActive(page, TEMPLATE, 'Deactivate');
  expect(await isActive(api, TEMPLATE)).toBeFalsy();
  const options = await offeredTemplates(page, event.id, TEMPLATE);
  await expect(options.filter({ hasText: new RegExp(`^${TEMPLATE}\\b`, 'i') })).toHaveCount(0);
  await expectScreen(dialog(page), 'object-template-deactivate.png');

  await setActive(page, TEMPLATE, 'Activate');
  expect(await isActive(api, TEMPLATE)).toBeTruthy();
});

test('Object template deactivated – object already used', async ({ page, api, ts, cleanup }) => {
  cleanup(await api.keepObjectTemplateActive(TEMPLATE));
  const event = await newEvent(api, cleanup, `QA template deactivated ${ts}`);
  const form = await reviewObject(page, event.id, TEMPLATE, { city: 'Luxembourg' });
  await form.getByRole('button', { name: 'Add Object' }).click();
  await expectDialogSaved(page);

  await setActive(page, TEMPLATE, 'Deactivate');
  const item = await objectItem(await openObjects(page, event.id), 'Luxembourg');
  await expect(item.getByText('Luxembourg', { exact: true }).first()).toBeVisible();
  await expectNoErrorPage(page);
  await expectScreen(item, 'object-template-deactivated-used.png');
  await setActive(page, TEMPLATE, 'Activate');
});

test('Object templates update', async ({ page, api }) => {
  test.setTimeout(5 * 60_000);
  const before = (await api.objectTemplates()).length;
  expect(await isActive(api, TEMPLATE)).toBeTruthy();

  await page.goto('/objectTemplates/index');
  await page.getByRole('link', { name: 'Update Object' }).click();
  await page.waitForURL(/\/objectTemplates$/, { timeout: 4 * 60_000 });
  await expect(page.getByText(/up to date|updated/i).first()).toBeAttached();
  await page.reload();
  await expectNoErrorPage(page);
  expect((await api.objectTemplates()).length).toBeGreaterThanOrEqual(before);
  expect(await isActive(api, TEMPLATE)).toBeTruthy();
  const activeRow = await templateRow(page, TEMPLATE);
  await expect(activeRow.locator('i[title="Enabled"]')).toBeVisible();
  await expectScreen(activeRow, 'object-template-update.png');
});

test('Object template search in Add Object', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA template search ${ts}`);
  const options = await offeredTemplates(page, event.id, 'domain');
  await expect(options.filter({ hasText: /^Domain-ip/i }).first()).toBeVisible();
  await page.keyboard.press('Escape');
  await pick(dialog(page).getByRole('combobox', { name: /Template/ }), 'domain', 'Domain-ip');
  await dialog(page).getByRole('button', { name: 'Next' }).click();
  await expect(dialog(page).getByRole('button', { name: /^Domain domain/ })).toBeVisible();
  await expectScreen(dialog(page), 'object-template-search.png');
});
