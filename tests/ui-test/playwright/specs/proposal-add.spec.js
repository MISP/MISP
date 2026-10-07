// ../../proposal/add/add.md
const {
  test, expect, expectNoErrorPage, blockedBy, expectScreen, openEvent, openTab, row,
  proposeChange, uniqueIp,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function eventWithIp(api, cleanup, info, value) {
  cleanup(() => api.deleteEventsByInfo(info));
  return api.createEvent({ info, attributes: [{ type: 'ip-dst', category: 'Network activity', value }] });
}

async function expectAttribute(page, eventId, value) {
  await openEvent(page, eventId);
  await expect(row(await openTab(page, 'Attributes'), value)).toBeVisible();
}

test('Proposal – change a value', async ({ page, api, ts, cleanup }) => {
  const [from, to] = [uniqueIp(ts), uniqueIp(Number(ts) + 1)];
  const event = await eventWithIp(api, cleanup, `QA proposal value ${ts}`, from);

  const form = await proposeChange(page, event.id, from, { value: to });
  await expect(page.getByText('The proposed Attribute has been saved')).toBeVisible();
  await expect(form).toBeHidden();
  await expectAttribute(page, event.id, from);
  await page.goto('/shadow_attributes/index/all:0');
  const proposal = row(page.getByRole('main'), to);
  await expect(proposal).toContainText(event.info ?? `QA proposal value ${ts}`);
  await expectScreen(proposal, 'proposal-change-value.png');
});

test('Proposal – delete an attribute', async ({ page, api, ts, cleanup }) => {
  const value = uniqueIp(ts);
  const event = await eventWithIp(api, cleanup, `QA proposal delete ${ts}`, value);

  const form = await proposeChange(page, event.id, value, { deletion: true });
  await expect(form).toBeHidden();
  await expectNoErrorPage(page);
  await expectAttribute(page, event.id, value);
  const proposals = await api.proposalsOf(event.id);
  expect(proposals.filter((p) => p.proposal_to_delete)).toHaveLength(1);
  await page.goto('/shadow_attributes/index/all:0');
  const proposal = row(page.getByRole('main'), value);
  await expect(proposal).toBeVisible();
  await expectScreen(proposal, 'proposal-delete.png');
});

test('Proposal – invalid value', async ({ page, api, ts, cleanup }) => {
  const value = uniqueIp(ts);
  const event = await eventWithIp(api, cleanup, `QA proposal invalid ${ts}`, value);

  const form = await proposeChange(page, event.id, value, { value: '999.1.1.1' });
  await expectNoErrorPage(page);
  await expect(page.getByText(/proposed Attribute could not be saved/).first()).toBeAttached();
  expect(await api.proposalsOf(event.id)).toHaveLength(0);
  blockedBy('New bug: an invalid proposed value closes the window with only "The proposed '
    + 'Attribute could not be saved." – the reason and the typed value are lost');
  await expect(form.getByText(/IP address has an invalid format/)).toBeVisible();
  await expect(form.locator('#ShadowAttributeValue')).toHaveValue('999.1.1.1');
  await expectScreen(form, 'proposal-invalid-value.png');
});

test('Proposal – no change', async ({ page, api, ts, cleanup }) => {
  const value = uniqueIp(ts);
  const event = await eventWithIp(api, cleanup, `QA proposal no change ${ts}`, value);

  const form = await proposeChange(page, event.id, value);
  await expect(form.or(page.getByText(/proposed Attribute/)).first()).toBeVisible();
  await expectNoErrorPage(page);
  // Refused with a message, or saved once: never several identical proposals.
  expect((await api.proposalsOf(event.id)).length).toBeLessThanOrEqual(1);
  await page.goto('/shadow_attributes/index/all:0');
  await expect(page.getByRole('main').getByRole('row').filter({ hasText: event.info ?? `QA proposal no change ${ts}` }))
    .toHaveCount((await api.proposalsOf(event.id)).length);
  await expectNoErrorPage(page);
  await expectScreen(page.getByRole('heading', { level: 1 }), 'proposal-no-change.png');
});

test('Proposal – emoji in the comment', async ({ page, api, ts, cleanup }) => {
  blockedBy('Bug 5 (an emoji in a proposal comment gives an internal error)');
  const value = uniqueIp(ts);
  const event = await eventWithIp(api, cleanup, `QA proposal emoji ${ts}`, value);

  const form = await proposeChange(page, event.id, value, { comment: 'QA proposal 🚀' });
  await expect(page.getByText('Request failed — please try again.')).toHaveCount(0);
  await expectNoErrorPage(page);
  await expect(form).toBeHidden();
  const [proposal] = await api.proposalsOf(event.id);
  expect(proposal?.comment).toBe('QA proposal 🚀');
  await page.goto('/shadow_attributes/index/all:0');
  await expectScreen(row(page.getByRole('main'), value), 'proposal-emoji-comment.png');
});
