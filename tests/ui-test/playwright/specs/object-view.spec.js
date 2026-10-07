// ../../object/view/objects.md
const {
  test, expect, expectNoErrorPage, expectDialogSaved, expectServerOk, blockedBy, expectScreen, dialog,
  reviewObject, openObjects, objectItem, openTab, row, uniqueIp,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const domainIp = (domain, ip) => ({
  name: 'domain-ip',
  attributes: [
    ...(domain ? [{ object_relation: 'domain', type: 'domain', value: domain }] : []),
    ...(ip ? [{ object_relation: 'ip', type: 'ip-dst', value: ip }] : []),
  ],
});

async function eventWithObjects(api, cleanup, info, objects) {
  cleanup(() => api.deleteEventsByInfo(info));
  return api.createEvent({ info, objects });
}

const objectsOf = async (api, eventId) => (await api.getEvent(eventId)).Object || [];
const valuesOf = (object) => object.Attribute.filter((a) => !a.deleted).map((a) => a.value).sort();

// Edit object -> change the fields -> Review; returns the form.
async function reviewEdit(page, item, change) {
  await item.getByRole('link', { name: 'Edit', exact: true }).first().click();
  const form = dialog(page);
  await expect(form.getByRole('button', { name: 'Save Changes' })).toBeAttached();
  await change(form);
  await form.getByRole('button', { name: 'Review', exact: true }).filter({ visible: true }).first().click();
  return form;
}

const field = (form, relation) => form
  .locator(`.attribute_row[data-object-relation="${relation}"] .Attribute_value`);

test('Object edit – change a value', async ({ page, api, ts, cleanup }) => {
  const [oldIp, newIp] = [uniqueIp(ts), uniqueIp(Number(ts) + 1)];
  const event = await eventWithObjects(api, cleanup, `QA object domain-ip ${ts}`,
    [domainIp('qa-test.example', oldIp)]);

  const item = await objectItem(await openObjects(page, event.id), 'qa-test.example');
  const form = await reviewEdit(page, item, (f) => field(f, 'ip').fill(newIp));
  await form.getByRole('button', { name: 'Save Changes' }).click();
  await expectDialogSaved(page);

  const [object] = await objectsOf(api, event.id);
  expect(valuesOf(object)).toEqual([newIp, 'qa-test.example'].sort());
  const updated = await objectItem(await openObjects(page, event.id), 'qa-test.example');
  await expect(updated.getByText(newIp, { exact: true })).toBeVisible();
  await expect(updated.getByText(oldIp, { exact: true })).toHaveCount(0);
  await expectScreen(updated.locator('table'), 'object-edit-value.png');
});

test('Object edit – remove the required attributes', async ({ page, api, ts, cleanup }) => {
  const ip = uniqueIp(ts);
  const event = await eventWithObjects(api, cleanup, `QA object domain-ip ${ts}`,
    [domainIp('qa-test.example', ip)]);

  const item = await objectItem(await openObjects(page, event.id), 'qa-test.example');
  const form = await reviewEdit(page, item, async (f) => {
    await field(f, 'domain').fill('');
    await field(f, 'ip').fill('');
    await f.getByRole('button', { name: /^Port port/ }).click();
    await field(f, 'port').fill('443');
  });
  await form.getByRole('button', { name: 'Save Changes' }).click();
  await expect(form.getByText('This template requires a value for at least one of: ip, domain, hostname.'))
    .toBeVisible();
  await expect(form).toBeVisible();
  const [object] = await objectsOf(api, event.id);
  expect(valuesOf(object)).toEqual([ip, 'qa-test.example'].sort());
  await expectNoErrorPage(page);
  await expectScreen(form, 'object-edit-remove-required.png');
});

test('Object soft-delete', async ({ page, api, ts, cleanup }) => {
  const event = await eventWithObjects(api, cleanup, `QA object soft delete ${ts}`,
    [domainIp('qa-soft.example')]);

  const item = await objectItem(await openObjects(page, event.id), 'qa-soft.example');
  await item.getByRole('link', { name: 'Delete', exact: true }).first().click();
  await dialog(page).getByRole('button', { name: 'Soft-delete' }).click();
  await expect(page.getByText('Object soft-deleted.')).toBeVisible();
  const tab = await openObjects(page, event.id);
  await expect(tab.getByText('qa-soft.example')).toHaveCount(0);
  await tab.getByRole('link', { name: 'Deleted' }).click();
  const deleted = page.getByRole('tabpanel').filter({ visible: true })
    .locator('.accordion-item').filter({ hasText: 'qa-soft.example' });
  await expect(deleted).toBeVisible();
  await expectScreen(deleted, 'object-soft-delete.png');
});

test('Object permanent delete', async ({ page, api, ts, cleanup }) => {
  const event = await eventWithObjects(api, cleanup, `QA object hard delete ${ts}`,
    [domainIp('qa-hard.example')]);

  // "Delete permanently" is offered on an object once it is soft-deleted.
  const item = await objectItem(await openObjects(page, event.id), 'qa-hard.example');
  await item.getByRole('link', { name: 'Delete', exact: true }).first().click();
  await dialog(page).getByRole('button', { name: 'Soft-delete' }).click();
  await expect(page.getByText('Object soft-deleted.')).toBeVisible();
  const tab = await openObjects(page, event.id);
  await tab.getByRole('link', { name: 'Deleted' }).click();
  const deleted = await objectItem(page.getByRole('tabpanel').filter({ visible: true }), 'qa-hard.example');
  await deleted.getByRole('link', { name: 'Delete permanently' }).first().click();
  await dialog(page).getByRole('button', { name: 'Delete permanently' }).click();
  await expect(page.getByText('Object deleted permanently.')).toBeVisible();

  const attributes = await openTab(page, 'Attributes');
  await attributes.getByRole('textbox').first().fill('qa-hard.example');
  await attributes.getByRole('textbox').first().press('Enter');
  await expect(page.getByRole('tabpanel').filter({ visible: true }).getByText('qa-hard.example', { exact: true }))
    .toHaveCount(0);
  const raw = await api.raw('GET', `/attributes/restSearch/value:qa-hard.example/eventid:${event.id}/deleted:[0,1]`);
  expect(raw.text).not.toContain('qa-hard.example');
  await expectScreen(page.getByRole('heading', { level: 1 }), 'object-hard-delete.png');
});

test('Object delete – several selected', async ({ page, api, ts, cleanup }) => {
  const event = await eventWithObjects(api, cleanup, `QA objects mass delete ${ts}`,
    [domainIp('qa-mass1.example'), domainIp('qa-mass2.example')]);

  const tab = await openObjects(page, event.id);
  for (const value of ['qa-mass1.example', 'qa-mass2.example']) {
    await tab.locator('.accordion-item').filter({ hasText: value })
      .getByRole('checkbox', { name: 'Select this object' }).check();
  }
  await page.getByRole('button', { name: 'Delete selected objects' }).click();
  const confirm = dialog(page);
  await confirm.getByLabel('Permanently delete (cannot be undone)').check();
  blockedBy('New bug: deleting selected objects is black-holed (/objects/deleteSelection has no '
    + 'form token, as in Bug 3)');
  await expectServerOk(confirm.getByRole('button', { name: 'Delete', exact: true }),
    '/objects/deleteSelection');
  await expect(page.getByText('Objects deleted permanently.')).toBeVisible();
  expect(await objectsOf(api, event.id)).toHaveLength(0);
  const after = await openObjects(page, event.id);
  await expect(after.locator('.accordion-item')).toHaveCount(0);
  await expectScreen(page.getByRole('heading', { level: 1 }), 'object-delete-selected.png');
});

test('Object filter', async ({ page, api, ts, cleanup }) => {
  const event = await eventWithObjects(api, cleanup, `QA object filter ${ts}`,
    [domainIp('qa-alpha.example'), domainIp('qa-beta.example')]);

  const tab = await openObjects(page, event.id);
  const items = tab.locator('.accordion-item');
  await expect(items).toHaveCount(2);
  const filter = tab.getByRole('textbox', { name: 'Filter objects…' });
  await filter.fill('alpha');
  await filter.press('Enter');
  const filtered = page.getByRole('tabpanel').filter({ visible: true }).locator('.accordion-item');
  await expect(filtered).toHaveCount(1);
  await expect(filtered.first()).toContainText('qa-alpha.example');
  await expectScreen(filtered.first(), 'object-filter.png');
  const box = page.getByRole('tabpanel').filter({ visible: true }).getByRole('textbox', { name: 'Filter objects…' });
  await box.fill('');
  await box.press('Enter');
  await expect(page.getByRole('tabpanel').filter({ visible: true }).locator('.accordion-item')).toHaveCount(2);
});

test('Object correlation between events', async ({ page, api, ts, cleanup }) => {
  const ip = uniqueIp(ts);
  const events = [];
  for (const n of [1, 2]) {
    const info = `QA correlation ${n} ${ts}`;
    cleanup(() => api.deleteEventsByInfo(info));
    events.push({ info, ...(await api.createEvent({ info })) });
    const form = await reviewObject(page, events[n - 1].id, 'domain-ip', { ip });
    await form.getByRole('button', { name: 'Add Object' }).click();
    await expectDialogSaved(page);
    await expect(page.getByRole('tab', { name: /^Objects/, selected: true })).toBeVisible();
  }
  const [first, second] = events;

  const correlation = await openTab(page, 'Correlation');
  await expect(correlation.getByRole('link', { name: new RegExp(`^${first.info}`) })).toBeVisible();
  const item = await objectItem(await openObjects(page, second.id), ip);
  await expect(row(item, ip).getByRole('link', { name: `#${first.id}`, exact: true })).toBeVisible();
  await expectScreen(row(item, ip), 'object-correlation.png');
});

test('Object edit – add a new attribute', async ({ page, api, ts, cleanup }) => {
  const ip = uniqueIp(ts);
  const event = await eventWithObjects(api, cleanup, `QA object add attribute ${ts}`,
    [domainIp('qa-object.example')]);

  const item = await objectItem(await openObjects(page, event.id), 'qa-object.example');
  const form = await reviewEdit(page, item, async (f) => {
    await f.getByRole('button', { name: /^Ip ip-dst/ }).click();
    await field(f, 'ip').fill(ip);
  });
  await form.getByRole('button', { name: 'Save Changes' }).click();
  await expectDialogSaved(page);
  const [object] = await objectsOf(api, event.id);
  expect(valuesOf(object)).toEqual([ip, 'qa-object.example'].sort());
  const updated = await objectItem(await openObjects(page, event.id), 'qa-object.example');
  await expect(updated.getByText(ip, { exact: true })).toBeVisible();
  await expectScreen(updated.locator('table'), 'object-edit-add-attribute.png');
});

test('Object card – attribute menu', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 22 (the attribute menu of an object is hidden behind the pagination bar)');
  const event = await eventWithObjects(api, cleanup, `QA object menu ${ts}`, [domainIp('qa-menu.example')]);

  const tab = await openObjects(page, event.id);
  await tab.getByRole('button', { name: 'Card View' }).click();
  const item = await objectItem(page.getByRole('tabpanel').filter({ visible: true }), 'qa-menu.example');
  // Card view lists the attributes without table rows: one attribute here.
  await item.getByRole('button', { name: 'Attribute actions' }).first().click();
  const menu = page.locator('.dropdown-menu.show');
  await expect(menu).toBeVisible();
  // Every entry must be the element under its own centre: nothing covers it.
  const covered = await menu.locator('a, button').evaluateAll((entries) => entries
    .filter((e) => {
      const r = e.getBoundingClientRect();
      const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      return !(hit && (hit === e || e.contains(hit)));
    }).map((e) => e.innerText.trim()));
  expect(covered, 'menu entries covered by another element').toEqual([]);
  await expectScreen(menu, 'object-card-attribute-menu.png');
});
