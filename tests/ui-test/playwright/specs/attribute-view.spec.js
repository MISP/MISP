// ../../attribute/view/attributes.md
const {
  test, expect, expectNoErrorPage, expectServerOk, blockedBy, expectScreen,
  fillAttribute, submitAttribute, openEvent, openTab, row, rowAction, dialog, eventCard,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const ip = (value, extra = {}) => ({ type: 'ip-dst', category: 'Network activity', value, ...extra });
const tab = (page) => page.getByRole('tabpanel').filter({ visible: true });

async function eventWith(api, cleanup, info, attributes = []) {
  const event = await api.createEvent({ info, attributes });
  cleanup(() => api.deleteEventsByInfo(info));
  return event;
}

test('Attribute edit – invalid value', async ({ page, api, ts, cleanup }) => {
  const event = await eventWith(api, cleanup, `QA attribute ip ${ts}`, [ip('198.51.100.30', { to_ids: true })]);

  await openEvent(page, event.id);
  await rowAction(row(await openTab(page, 'Attributes'), '198.51.100.30'), 'Edit');
  const form = dialog(page);
  await form.getByRole('textbox', { name: /Enter the indicator value/ }).fill('999.1.1.1');
  await form.getByRole('button', { name: 'Save Changes' }).click();
  const message = 'IP address has an invalid format.';
  await Promise.race([form.getByText(message).first().waitFor(), form.waitFor({ state: 'hidden' })]);

  expect((await api.getEvent(event.id)).Attribute[0].value, 'MISP changed the value').toBe('198.51.100.30');
  expect(await form.isVisible(), 'MISP closed the form without the reason').toBe(true);
  await expect(form.getByText(message).first()).toBeVisible();
  await expectScreen(form, 'attribute-edit-invalid.png');
});

test('Attribute edit – IDS flag', async ({ page, api, ts, cleanup }) => {
  const event = await eventWith(api, cleanup, `QA attribute ip ${ts}`, [ip('198.51.100.30', { to_ids: true })]);

  await openEvent(page, event.id);
  await rowAction(row(await openTab(page, 'Attributes'), '198.51.100.30'), 'Edit');
  await dialog(page).getByRole('checkbox', { name: /^For IDS/ }).uncheck();
  await dialog(page).getByRole('button', { name: 'Save Changes' }).click();

  const r = row(tab(page), '198.51.100.30');
  await expect(r.getByRole('button', { name: /^IDS inactive/ })).toBeVisible();
  expect((await api.getEvent(event.id)).Attribute[0].to_ids).toBe(false);
  await expectScreen(r, 'attribute-edit-ids.png');
});

test('Attribute soft-delete and restore', async ({ page, api, ts, cleanup }) => {
  const event = await eventWith(api, cleanup, `QA attribute restore ${ts}`);

  await openEvent(page, event.id);
  await submitAttribute(await fillAttribute(page, { ...ip('198.51.100.50') }));
  let attributes = await openTab(page, 'Attributes');
  await rowAction(row(attributes, '198.51.100.50'), 'Delete');
  await dialog(page).getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(row(attributes, '198.51.100.50')).toHaveCount(0);

  await attributes.getByRole('link', { name: /^Deleted/ }).click();
  attributes = tab(page);
  await expect(row(attributes, '198.51.100.50')).toBeVisible();
  await rowAction(row(attributes, '198.51.100.50'), 'Restore');
  await dialog(page).getByRole('button', { name: 'Restore', exact: true }).click();
  await expect(dialog(page)).toHaveCount(0);
  await attributes.getByRole('link', { name: /^Deleted/ }).click();

  const r = row(tab(page), '198.51.100.50');
  await expect(r).toBeVisible();
  expect((await api.getEvent(event.id)).Attribute[0].deleted).toBe(false);
  await expectScreen(r, 'attribute-soft-delete-restore.png');
});

test('Attribute delete – correlation removed', async ({ page, api, ts, cleanup }) => {
  const first = await eventWith(api, cleanup, `QA delete correlation 1 ${ts}`, [ip('198.51.100.51')]);
  const second = await eventWith(api, cleanup, `QA delete correlation 2 ${ts}`, [ip('198.51.100.51')]);

  await openEvent(page, second.id);
  await rowAction(row(await openTab(page, 'Attributes'), '198.51.100.51'), 'Delete');
  await dialog(page).getByRole('checkbox', { name: /^Permanently delete/ }).check();
  await dialog(page).getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(row(tab(page), '198.51.100.51')).toHaveCount(0);

  await openEvent(page, first.id);
  await expect(eventCard(page, 'related').getByText(second.info)).toHaveCount(0);
  await expectScreen(eventCard(page, 'related'), 'attribute-delete-correlation.png');
});

test('Attribute filter in an event', async ({ page, api, ts, cleanup }) => {
  const event = await eventWith(api, cleanup, `QA attribute filter ${ts}`);
  const domain = (value) => ({ category: 'Network activity', type: 'domain', value });

  await openEvent(page, event.id);
  await submitAttribute(await fillAttribute(page, domain('qa-alpha.example')));
  await expect(dialog(page)).toHaveCount(0);
  await submitAttribute(await fillAttribute(page, domain('qa-beta.example')));
  const attributes = await openTab(page, 'Attributes');
  const filter = attributes.getByRole('textbox', { name: /Filter by attribute value/ });
  await filter.fill('alpha');
  await filter.press('Enter');

  await expect(row(tab(page), 'qa-alpha.example')).toBeVisible();
  await expect(row(tab(page), 'qa-beta.example')).toHaveCount(0);
  await expectScreen(tab(page).getByRole('table'), 'attribute-filter-event.png');

  const cleared = tab(page).getByRole('textbox', { name: /Filter by attribute value/ });
  await cleared.fill('');
  await cleared.press('Enter');
  await expect(row(tab(page), 'qa-alpha.example')).toBeVisible();
  await expect(row(tab(page), 'qa-beta.example')).toBeVisible();
});

test('Attribute correlation icon', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 11 (the correlation icon: the server disables the correlation, the icon still shows it enabled)');
  const event = await eventWith(api, cleanup, `QA correlation toggle ${ts}`, [ip('198.51.100.181')]);

  await openEvent(page, event.id);
  const r = row(await openTab(page, 'Attributes'), '198.51.100.181');
  await r.getByRole('button', { name: /^Correlation enabled/ }).click();
  await expectServerOk(dialog(page).getByRole('button', { name: 'Disable correlation' }),
    '/attributes/toggleCorrelation/');
  await expect(page.getByText('Correlation disabled').first()).toBeVisible();
  const [attribute] = (await api.getEvent(event.id)).Attribute;
  expect(attribute.disable_correlation, 'correlation disabled on the server').toBe(true);
  await expect(r.getByRole('button', { name: /^Correlation disabled/ }),
    'the icon shows the correlation as disabled').toBeVisible();
  await r.getByRole('button', { name: /^Correlation disabled/ }).click();
  await expectServerOk(dialog(page).getByRole('button', { name: 'Enable correlation' }),
    '/attributes/toggleCorrelation/');
  await expect(page.getByText('Correlation enabled').first()).toBeVisible();
  await expect(page.getByText('error: undefined')).toHaveCount(0);
  await expectScreen(r, 'attribute-correlation-toggle.png');
});

test('Attributes tab – select attributes', async ({ page, api, ts, cleanup }) => {
  const event = await eventWith(api, cleanup, `QA attribute select ${ts}`,
    [ip('198.51.100.220'), ip('198.51.100.221')]);

  await openEvent(page, event.id);
  const attributes = await openTab(page, 'Attributes');
  await row(attributes, '198.51.100.220').getByRole('checkbox').check();
  await expect(page.getByText('Selected items: 1')).toBeVisible();
  await attributes.getByRole('row').first().getByRole('checkbox').check();
  await expect(page.getByText('Selected items: 2')).toBeVisible();
  await expect(page.getByRole('button', { name: /Delete selected/ })).toBeVisible();
  await expectScreen(page.getByText('Selected items: 2').locator('xpath=ancestor::*[.//button][1]'),
    'attribute-tab-select.png');
});
