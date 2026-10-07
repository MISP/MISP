// ../../import-export/freetext/freetext.md
const {
  test, expect, expectNoErrorPage, expectScreen, freetextImport, freetextResults, openEvent, dialog,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function eventFor(page, api, cleanup, info) {
  const event = await api.createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));
  await openEvent(page, event.id);
  return event;
}

test('Freetext – defanged indicators', async ({ page, api, ts, cleanup }) => {
  await eventFor(page, api, cleanup, `QA freetext defanged ${ts}`);
  const review = await freetextImport(page, 'hxxp://evil[.]example/login.php?id=1 and 198.51.100[.]120');

  expect(await freetextResults(review)).toEqual([
    ['http://evil.example/login.php?id=1', 'url'],
    ['198.51.100.120', 'ip-dst'],
  ]);
  await expectScreen(review, 'freetext-defanged.png');
});

test('Freetext – punctuation and duplicates', async ({ page, api, ts, cleanup }) => {
  await eventFor(page, api, cleanup, `QA freetext punctuation ${ts}`);
  const review = await freetextImport(page, 'See (https://qa-paren.example/path). Again 198.51.100.121 198.51.100.121.');

  expect((await freetextResults(review)).map(([value]) => value))
    .toEqual(['https://qa-paren.example/path', '198.51.100.121']);
  await expectScreen(review, 'freetext-punctuation.png');
});

test('Freetext – types recognised', async ({ page, api, ts, cleanup }) => {
  await eventFor(page, api, cleanup, `QA freetext types ${ts}`);
  const review = await freetextImport(page, '2001:db8::1 44d88612fea8a8f36de82e1278abb02f attacker@evil.example CVE-2024-3400');

  expect((await freetextResults(review)).map(([, type]) => type))
    .toEqual(['ip-dst', 'md5', 'email-src', 'vulnerability']);
  await expectScreen(review, 'freetext-types.png');
});

test('Freetext – no indicator', async ({ page, api, ts, cleanup }) => {
  const event = await eventFor(page, api, cleanup, `QA freetext nothing ${ts}`);
  await page.getByRole('link', { name: 'Populate from' }).click();
  const form = dialog(page);
  await form.getByRole('button', { name: /^Freetext Import/ }).click();
  await form.getByRole('textbox', { name: 'IOCs' }).fill('nothing to see here');
  await form.getByRole('button', { name: 'Run Freetext Import' }).click();

  const message = page.getByText('No indicators were detected in the provided text.').first();
  await expect(message).toBeVisible();
  expect((await api.getEvent(event.id)).Attribute).toHaveLength(0);
  await expectScreen(message, 'freetext-nothing.png');
});

test('Freetext – bulk change before import', async ({ page, api, ts, cleanup }) => {
  const event = await eventFor(page, api, cleanup, `QA freetext bulk ${ts}`);
  const review = await freetextImport(page, '198.51.100.123 198.51.100.124');

  await review.locator('#ftChangeFrom').selectOption('ip-dst');
  await review.locator('#ftChangeTo').selectOption('ip-src');
  await review.getByRole('button', { name: 'Change all' }).click();
  await review.getByRole('textbox', { name: 'Comment…' }).fill('QA bulk');
  await review.getByRole('button', { name: 'Apply' }).click();
  // No bulk "No IDS" in Overmind: turn IDS off on each line.
  const idsOn = review.locator('.ft-ids[data-on="1"]');
  while (await idsOn.count()) await idsOn.first().click();
  await expectScreen(review, 'freetext-bulk-review.png');
  await review.getByRole('button', { name: 'Create attributes' }).click();
  await expect(dialog(page)).toHaveCount(0);

  const attributes = (await api.getEvent(event.id)).Attribute;
  expect(attributes.map((a) => [a.value, a.type, a.comment, a.to_ids]).sort()).toEqual([
    ['198.51.100.123', 'ip-src', 'QA bulk', false],
    ['198.51.100.124', 'ip-src', 'QA bulk', false],
  ]);
});

test('Freetext – create as proposals', async ({ page, api, ts, cleanup }) => {
  const event = await eventFor(page, api, cleanup, `QA freetext proposals ${ts}`);
  const review = await freetextImport(page, '198.51.100.125');
  await review.getByRole('checkbox', { name: 'Create as proposals instead of attributes' }).check();
  await review.getByRole('button', { name: /Create/ }).last().click();
  await expect(dialog(page)).toHaveCount(0);

  expect((await api.getEvent(event.id)).Attribute).toHaveLength(0);
  await page.goto('/shadow_attributes/index/all:0');
  const proposal = page.getByRole('main').getByRole('row').filter({ hasText: '198.51.100.125' })
    .filter({ has: page.getByRole('link', { name: `#${event.id}`, exact: true }) });
  await expect(proposal).toBeVisible();
  await expectScreen(proposal, 'freetext-proposals.png');
});
