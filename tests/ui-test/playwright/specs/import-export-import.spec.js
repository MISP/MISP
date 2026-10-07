// ../../import-export/import/import.md
const crypto = require('crypto');
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, dialog,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function openImport(page) {
  await page.goto('/events/index');
  await page.getByRole('button', { name: 'More actions' }).first().click();
  await page.locator('.dropdown-menu.show').getByRole('link', { name: 'Import Event' }).click();
  return dialog(page);
}

async function importMisp(page, json) {
  const form = await openImport(page);
  await form.getByRole('textbox', { name: 'Paste a MISP export' }).fill(json);
  await form.getByRole('button', { name: 'Import MISP file' }).click();
  return form;
}

// A MISP JSON document of an event that is not on the instance.
function mispExport(info) {
  return JSON.stringify({
    Event: {
      uuid: crypto.randomUUID(), info, date: '2026-10-01', distribution: '0', threat_level_id: '4', analysis: '0',
      Orgc: { name: 'QA external org', uuid: crypto.randomUUID() },
      Attribute: [{ uuid: crypto.randomUUID(), type: 'ip-dst', category: 'Network activity', value: '198.51.100.127', to_ids: true }],
      Object: [{
        uuid: crypto.randomUUID(), name: 'domain-ip', 'meta-category': 'network', distribution: '5',
        template_uuid: '43b3b146-77eb-4931-b4cc-b66c60f28734', template_version: '11',
        Attribute: [{ uuid: crypto.randomUUID(), object_relation: 'domain', type: 'domain', category: 'Network activity', value: 'qa-import.example' }],
      }],
      Tag: [{ name: 'tlp:green' }],
    },
  });
}

test('Import – MISP JSON', async ({ page, api, ts, cleanup }) => {
  const info = `QA import json ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));
  await importMisp(page, mispExport(info));

  await expectNoErrorPage(page);
  await expect.poll(async () => (await api.findEvents(info)).length).toBe(1);
  const event = await api.getEvent((await api.findEvents(info))[0].id);
  expect(event.Attribute.map((a) => a.value)).toContain('198.51.100.127');
  expect(event.Object.map((o) => o.name)).toContain('domain-ip');
  expect(event.Tag.map((t) => t.name)).toContain('tlp:green');
  await expectScreen(page.getByRole('heading', { level: 1 }).first(), 'import-misp-json.png', { hide: [ts] });
});

test('Import – event already present', async ({ page, api, ts, cleanup }) => {
  const info = `QA export csv formula ${ts}`;
  const original = await api.createEvent({ info, attributes: [{ type: 'ip-dst', category: 'Network activity', value: '198.51.100.128' }] });
  cleanup(() => api.deleteEventsByInfo(info));
  const json = JSON.stringify(await api.get(`/events/view/${original.id}`));

  await importMisp(page, json);
  await expectNoErrorPage(page);
  const message = page.getByText(/1 already existing/).first();
  await expect(message).toBeVisible();
  expect(await api.findEvents(info)).toHaveLength(1);
  await expectScreen(message, 'import-duplicate.png');
});

test('Import – invalid file', async ({ page }) => {
  blockedBy('New bug: "Import MISP file" with text that is not JSON does nothing – no request, no message');
  const form = await importMisp(page, '{ not json');
  await expectNoErrorPage(page);
  const message = page.getByText(/Invalid JSON input/i).first();
  await expect(message).toBeVisible();
  await expectScreen(message, 'import-invalid.png');
});

test('Import – take ownership', async ({ page, api, ts, cleanup }) => {
  blockedBy('Missing feature: the Import Event window has no "Take ownership of the event" option');
  const info = `QA import ownership ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));
  const form = await openImport(page);
  await form.getByRole('textbox', { name: 'Paste a MISP export' }).fill(mispExport(info));
  const ownership = form.getByRole('checkbox', { name: /Take ownership/i });
  await expect(ownership, 'a "Take ownership of the event" option').toBeVisible({ timeout: 5_000 });
  await ownership.check();
  await form.getByRole('button', { name: 'Import MISP file' }).click();

  await expect.poll(async () => (await api.findEvents(info))[0]?.Orgc?.name ?? (await api.findEvents(info))[0]?.orgc_id)
    .toBeTruthy();
  const event = await api.getEvent((await api.findEvents(info))[0].id);
  expect(event.Orgc.name).toBe('ADMIN');
});

test('Import – STIX 2', async ({ page, api, ts, cleanup }, testInfo) => {
  const bundle = {
    type: 'bundle', id: `bundle--${crypto.randomUUID()}`,
    objects: [{
      type: 'indicator', spec_version: '2.1', id: `indicator--${crypto.randomUUID()}`,
      created: '2026-10-01T10:00:00.000Z', modified: '2026-10-01T10:00:00.000Z',
      name: `QA stix ${ts}`, pattern: "[ipv4-addr:value = '198.51.100.126']", pattern_type: 'stix', valid_from: '2026-10-01T10:00:00Z',
    }],
  };
  const form = await openImport(page);
  await form.getByRole('button', { name: /^STIX 2\.x/ }).click();
  const file = form.locator('#s2StixFile');
  const section = file.locator('xpath=ancestor::form[1]');
  await file.setInputFiles({
    name: 'qa-stix.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(bundle)),
  });
  await section.getByRole('button', { name: /Import|Upload/ }).last().click();

  await expect(page.getByText('STIX document imported.')).toBeVisible();
  await expect(page).toHaveURL(/\/events\/view2\/\d+/);
  const eventId = page.url().match(/view2\/(\d+)/)[1];
  cleanup(() => api.post(`/events/delete/${eventId}`));
  await expectNoErrorPage(page);
  const event = await api.getEvent(eventId);
  const values = [...event.Attribute, ...(event.Object || []).flatMap((o) => o.Attribute)].map((a) => a.value);
  expect(values).toContain('198.51.100.126');
  await expectScreen(page.getByRole('heading', { level: 1 }).first(), 'import-stix2.png', { hide: [ts] });
});
