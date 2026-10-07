// ../../object/add/add.md
const {
  test, expect, expectNoErrorPage, expectDialogSaved, blockedBy, expectScreen,
  reviewObject, openObjects, openEvent, uniqueIp,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function newEvent(api, cleanup, info, options = {}) {
  cleanup(() => api.deleteEventsByInfo(info));
  return api.createEvent({ info, ...options });
}

const objectsOf = async (api, eventId) => (await api.getEvent(eventId)).Object || [];

// "Submit" of the plans is the "Add Object" button of the Review step.
const submit = (form) => form.getByRole('button', { name: 'Add Object' }).click();

// Saved: the window closes and the event reopens on its Objects tab.
async function submitObject(page, form) {
  await submit(form);
  await expectDialogSaved(page);
  await expect(page.getByRole('tab', { name: /^Objects/, selected: true })).toBeVisible();
}

// Refused: the window stays open with `message`, and nothing is saved.
async function expectRefused(page, api, event, form, message) {
  await expect(form.getByText(message).first()).toBeVisible();
  await expect(form).toBeVisible();
  expect(await objectsOf(api, event.id)).toHaveLength(0);
  await expectNoErrorPage(page);
}

test('Object add – domain-ip', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA object domain-ip ${ts}`);
  const ip = uniqueIp(ts);
  const form = await reviewObject(page, event.id, 'domain-ip', { domain: 'qa-test.example', ip });
  await submitObject(page, form);

  const tab = page.getByRole('tabpanel').filter({ visible: true });
  await expect(tab.getByText('qa-test.example').first()).toBeVisible();
  const [object] = await objectsOf(api, event.id);
  expect(object.Attribute.map((a) => a.value).sort()).toEqual([ip, 'qa-test.example'].sort());
  await expectScreen(tab.locator('.accordion-item').first(), 'object-add-domain-ip.png');
});

test('Object add – no attribute', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA object empty ${ts}`);
  const form = await reviewObject(page, event.id, 'domain-ip');
  await submit(form);
  // The "required one of" check of the template answers before the "no attribute" one.
  await expectRefused(page, api, event, form, /no attributes were set|requires a value for at least one of/);
  await expectScreen(form, 'object-add-empty.png');
});

test('Object add – required one of missing', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA object required one of ${ts}`);
  const form = await reviewObject(page, event.id, 'domain-ip', { port: '443' });
  await submit(form);
  await expectRefused(page, api, event, form,
    'This template requires a value for at least one of: ip, domain, hostname.');
  await expect(form.locator('.attribute_row[data-object-relation="port"] .Attribute_value'))
    .toHaveValue('443');
  await expectScreen(form, 'object-add-required-one-of.png');
});

test('Object add – required attribute missing', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA object required ${ts}`);
  const form = await reviewObject(page, event.id, 'ai-dataset-component',
    { 'dataset-version': '1.0' });
  await submit(form);
  await expectRefused(page, api, event, form, new RegExp('required attribute is not set '
    + '\\(dataset-name\\)|requires a value for: dataset-name'));
  await expectScreen(form, 'object-add-required.png');
});

test('Object add – invalid attribute value', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA object invalid ip ${ts}`);
  const form = await reviewObject(page, event.id, 'domain-ip',
    { domain: 'qa-test.example', ip: '999.1.1.1' });
  await submit(form);
  await expectRefused(page, api, event, form, 'ip: IP address has an invalid format.');
  await expect(form.locator('.attribute_row[data-object-relation="ip"] .Attribute_value'))
    .toHaveValue('999.1.1.1');
  await expectScreen(form, 'object-add-invalid-value.png');
});

test('Object add – first seen after last seen', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA object seen order ${ts}`);
  const form = await reviewObject(page, event.id, 'domain-ip', { domain: 'qa-test.example' },
    { firstSeen: '01/10/2026 12:00:00', lastSeen: '01/01/2026 12:00:00' });
  await submit(form);
  await expectRefused(page, api, event, form, 'Last seen cannot be earlier than first seen.');
  await expectScreen(form, 'object-add-seen-order.png');
});

test('Object add – same object twice', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA object duplicate ${ts}`);
  await submitObject(page, await reviewObject(page, event.id, 'domain-ip', { domain: 'qa-dup.example' }));

  const form = await reviewObject(page, event.id, 'domain-ip', { domain: 'qa-dup.example' });
  // MISP warns in the Review step, then saves a second object if asked to.
  await expect(form.getByText(/already overlaps this one/)).toBeVisible();
  await expectScreen(form.getByText(/already overlaps this one/), 'object-add-duplicate-warning.png');
  await submitObject(page, form);
  expect(await objectsOf(api, event.id)).toHaveLength(2);
  await expectNoErrorPage(page);
});

test('Object add – on a published event', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA object published ${ts}`, { publish: true });
  await expect.poll(async () => (await api.getEvent(event.id)).published).toBe(true);

  const form = await reviewObject(page, event.id, 'domain-ip', { domain: 'qa-published.example' });
  await submitObject(page, form);
  expect(await objectsOf(api, event.id)).toHaveLength(1);
  expect((await api.getEvent(event.id)).published).toBe(false);
  await openEvent(page, event.id);
  await expect(page.getByText('Unpublished', { exact: true }).filter({ visible: true })).toBeVisible();
  await expectScreen(page.getByRole('heading', { level: 1 }), 'object-add-published-event.png');
});

test('Object add – review then submit', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(api, cleanup, `QA object nova-rule ${ts}`);
  const form = await reviewObject(page, event.id, 'nova-rule');
  await submit(form);
  await expect(page.getByText(/tripped the cross-site request forgery/)).toHaveCount(0);
  await expectNoErrorPage(page);
  const saved = (await objectsOf(api, event.id)).length > 0;
  if (!saved) await expect(form.getByText(/required|could not save/i).first()).toBeVisible();
  await expectScreen(form.or(page.getByRole('heading', { level: 1 })).first(), 'object-add-review-submit.png');
});
