// ../../attribute/add/add.md
const {
  test, expect, expectNoErrorPage, expectScreen, blockedBy, fillAttribute, submitAttribute,
  openEvent, openTab, row, dialog, eventSummary, eventCard, expectAfterReload,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

const net = (type, value, extra = {}) => ({ category: 'Network activity', type, value, ...extra });

// An event of its own for each test, open on its page.
async function newEvent(page, api, cleanup, info) {
  const event = await api.createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));
  await openEvent(page, event.id);
  return event;
}

const REFUSED_BUG = 'New bug: a refused attribute closes the form and only shows "Attribute could '
  + 'not be saved." – the reason and the typed value are lost';

// The form is refused: the attribute is not saved (the event keeps `count`
// attributes), the form stays open with `message` and the typed `value`.
async function expectRefused(page, api, event, form, message, { value, count = 0 } = {}) {
  await Promise.race([form.getByText(message).first().waitFor(), form.waitFor({ state: 'hidden' })]);
  expect((await api.getEvent(event.id)).Attribute, 'MISP saved the attribute').toHaveLength(count);
  expect(await form.isVisible(),
    'MISP closed the form: only "Attribute could not be saved." is shown, the reason and the value are lost')
    .toBe(true);
  await expect(form.getByText(message).first()).toBeVisible();
  if (value) await expect(form.getByRole('textbox', { name: /Enter the indicator value/ })).toHaveValue(value);
  await expectNoErrorPage(page);
}

test('Attribute add – ip-dst', async ({ page, api, ts, cleanup }) => {
  await newEvent(page, api, cleanup, `QA attribute ip ${ts}`);
  await submitAttribute(await fillAttribute(page, net('ip-dst', '198.51.100.30', { ids: true })));

  const attributes = await openTab(page, 'Attributes');
  const r = row(attributes, '198.51.100.30');
  await expect(r.getByRole('cell', { name: 'ip-dst', exact: true })).toBeVisible();
  await expect(r.getByRole('button', { name: /^IDS active/ })).toBeVisible();
  await expectScreen(r, 'attribute-add-ip.png');
});

test('Attribute add – invalid IP', async ({ page, api, ts, cleanup }) => {
  blockedBy(REFUSED_BUG);
  const event = await newEvent(page, api, cleanup, `QA attribute invalid ip ${ts}`);
  const form = await fillAttribute(page, net('ip-dst', '999.1.1.1'));
  await submitAttribute(form);

  await expectRefused(page, api, event, form, 'IP address has an invalid format.', { value: '999.1.1.1' });
  await expectScreen(form, 'attribute-add-invalid-ip.png');
});

test('Attribute add – invalid md5', async ({ page, api, ts, cleanup }) => {
  blockedBy(REFUSED_BUG);
  const event = await newEvent(page, api, cleanup, `QA attribute invalid md5 ${ts}`);
  const form = await fillAttribute(page, { category: 'Payload delivery', type: 'md5', value: 'abc123' });
  await submitAttribute(form);

  await expectRefused(page, api, event, form, /Checksum has an invalid length or format \(expected: 32 hexadecimal characters\)/);
  await expectScreen(form, 'attribute-add-invalid-md5.png');
});

test('Attribute add – port out of range', async ({ page, api, ts, cleanup }) => {
  blockedBy(REFUSED_BUG);
  const event = await newEvent(page, api, cleanup, `QA attribute invalid port ${ts}`);
  const form = await fillAttribute(page, net('ip-dst|port', '198.51.100.31|70000'));
  await submitAttribute(form);

  await expectRefused(page, api, event, form, 'Port numbers have to be integers between 1 and 65535.');
  await expectScreen(form, 'attribute-add-invalid-port.png');
});

test('Attribute add – duplicate', async ({ page, api, ts, cleanup }) => {
  blockedBy(REFUSED_BUG);
  const event = await newEvent(page, api, cleanup, `QA attribute duplicate ${ts}`);
  await submitAttribute(await fillAttribute(page, net('domain', 'qa-dup.example')));
  await expect(dialog(page)).toHaveCount(0);
  const form = await fillAttribute(page, net('domain', 'qa-dup.example'));
  await submitAttribute(form);

  await expectRefused(page, api, event, form, 'A similar attribute already exists for this event.', { count: 1 });
  await expectScreen(form, 'attribute-add-duplicate.png');
});

test('Attribute add – duplicate after normalisation', async ({ page, api, ts, cleanup }) => {
  blockedBy(REFUSED_BUG);
  const event = await newEvent(page, api, cleanup, `QA attribute duplicate case ${ts}`);
  await submitAttribute(await fillAttribute(page, net('domain', 'qa-case.example')));
  await expect(dialog(page)).toHaveCount(0);
  const form = await fillAttribute(page, net('domain', 'QA-Case.Example.'));
  await submitAttribute(form);

  await expectRefused(page, api, event, form, 'A similar attribute already exists for this event.', { count: 1 });
  await expectScreen(form, 'attribute-add-duplicate-normalised.png');
});

test('Attribute add – domain normalisation', async ({ page, api, ts, cleanup }) => {
  await newEvent(page, api, cleanup, `QA attribute domain normalised ${ts}`);
  await submitAttribute(await fillAttribute(page, net('domain', 'QA-Norm.Example.')));

  const r = row(await openTab(page, 'Attributes'), 'qa-norm.example');
  await expect(r).toBeVisible();
  await expectScreen(r, 'attribute-add-domain-normalised.png');
});

test('Attribute add – internationalised domain', async ({ page, api, ts, cleanup }) => {
  await newEvent(page, api, cleanup, `QA attribute idn ${ts}`);
  await submitAttribute(await fillAttribute(page, net('domain', 'bücher.example')));

  const r = row(await openTab(page, 'Attributes'), 'xn--bcher-kva.example');
  await expect(r).toBeVisible();
  await expectScreen(r, 'attribute-add-idn.png');
});

test('Attribute add – with First Seen', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(page, api, cleanup, `QA attribute first seen ${ts}`);
  const form = await fillAttribute(page, net('ip-dst', '198.51.100.32', { firstSeen: '01/09/2026 10:00:00' }));
  await submitAttribute(form);

  await expect(dialog(page)).toHaveCount(0);
  await expect(page.getByText(/cross-site request forgery/i)).toHaveCount(0);
  await expectNoErrorPage(page);
  const [attribute] = (await api.getEvent(event.id)).Attribute;
  expect(attribute.first_seen).toMatch(/^2026-09-01T10:00:00/);
  await expectScreen(row(await openTab(page, 'Attributes'), '198.51.100.32'), 'attribute-add-first-seen.png');
});

test('Attribute add – First Seen after Last Seen', async ({ page, api, ts, cleanup }) => {
  const event = await newEvent(page, api, cleanup, `QA attribute seen order ${ts}`);
  const form = await fillAttribute(page, net('ip-dst', '198.51.100.33', {
    firstSeen: '01/10/2026 10:00:00', lastSeen: '01/01/2026 10:00:00',
  }));
  await submitAttribute(form);

  await expectRefused(page, api, event, form, 'Last seen cannot be earlier than first seen.');
  await expectScreen(form, 'attribute-add-seen-order.png');
});

test('Attribute add – types limited by category', async ({ page, api, ts, cleanup }) => {
  await newEvent(page, api, cleanup, `QA attribute category types ${ts}`);
  await page.getByRole('link', { name: 'Add Attribute' }).click();
  const form = dialog(page);
  const { pick } = require('../helpers');
  await pick(form.locator('#AttributeCategory + .ts-wrapper').getByRole('combobox'), 'Financial fraud');
  const types = await form.locator('#AttributeType option').allTextContents();

  expect(types).toEqual(expect.arrayContaining(['iban', 'bic']));
  expect(types).not.toContain('ip-dst');
  await expectScreen(form, 'attribute-add-category-types.png');
});

test('Attribute add – on a published event', async ({ page, api, ts, cleanup }) => {
  const event = await api.createEvent({ info: `QA attribute published ${ts}`, publish: true });
  cleanup(() => api.deleteEventsByInfo(event.info));
  await openEvent(page, event.id);
  await expectAfterReload(page, () => expect(page.getByRole('main')).toContainText(/Publication\s*Published/));

  await submitAttribute(await fillAttribute(page, net('ip-dst', '198.51.100.34')));
  await expect(row(await openTab(page, 'Attributes'), '198.51.100.34')).toBeVisible();
  await openEvent(page, event.id);
  await expect(page.getByRole('main')).toContainText(/Publication\s*Unpublished/);
  await expectScreen(eventSummary(page), 'attribute-add-published-event.png');
});

test('Attribute add – warninglist hit', async ({ page, api, ts, cleanup }) => {
  const list = 'List of known IPv4 public DNS resolvers';
  cleanup(await api.enableWarninglist(list));
  const event = await newEvent(page, api, cleanup, `QA attribute warninglist ${ts}`);
  await submitAttribute(await fillAttribute(page, net('ip-dst', '8.8.8.8', { ids: true })));
  await expect(row(await openTab(page, 'Attributes'), '8.8.8.8')).toBeVisible();

  // Overmind lists the warninglist hits in the "Warning Lists" panel of the event.
  await openEvent(page, event.id);
  await expectAfterReload(page,
    () => expect(eventCard(page, 'warninglist').getByRole('link', { name: list })).toBeVisible());
  await expectScreen(eventCard(page, 'warninglist'), 'attribute-add-warninglist.png');
});

test('Attribute add – correlation disabled', async ({ page, api, ts, cleanup }) => {
  const first = await api.createEvent({
    info: `QA correlation off 1 ${ts}`, attributes: [{ ...net('ip-dst', '198.51.100.35') }],
  });
  cleanup(() => api.deleteEventsByInfo(first.info));
  await newEvent(page, api, cleanup, `QA correlation off 2 ${ts}`);
  await submitAttribute(await fillAttribute(page, net('ip-dst', '198.51.100.35', { disableCorrelation: true })));

  const r = row(await openTab(page, 'Attributes'), '198.51.100.35');
  await expect(r).toBeVisible();
  await expect(r.getByRole('link', { name: `#${first.id}`, exact: true })).toHaveCount(0);
  await openTab(page, 'General');
  await expect(eventCard(page, 'related').getByText(first.info)).toHaveCount(0);
  await expectScreen(eventCard(page, 'related'), 'attribute-add-no-correlation.png');
});

test('Attribute add – emoji in the comment', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 5 (an emoji in the attribute comment gives "An Internal Error Has Occurred.")');
  await newEvent(page, api, cleanup, `QA attribute emoji ${ts}`);
  const form = await fillAttribute(page, net('ip-dst', '198.51.100.60', { comment: 'QA comment 🚀' }));
  await submitAttribute(form);

  await expectNoErrorPage(page);
  const r = row(await openTab(page, 'Attributes'), '198.51.100.60');
  await expect(r).toContainText('QA comment 🚀');
  await expectScreen(r, 'attribute-add-emoji-comment.png');
});
