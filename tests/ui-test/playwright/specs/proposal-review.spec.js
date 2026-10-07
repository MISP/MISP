// ../../proposal/review/review.md
const {
  test, expect, expectNoErrorPage, expectServerOk, blockedBy, expectScreen, openEvent, openTab, row,
  dialog, proposeChange, openProposals, PROPOSAL_BUG, uniqueIp,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function eventWithIps(api, cleanup, info, values, options = {}) {
  cleanup(() => api.deleteEventsByInfo(info));
  return api.createEvent({
    info, ...options, attributes: values.map((value) => ({ type: 'ip-dst', category: 'Network activity', value })),
  });
}

async function propose(page, eventId, from, change) {
  const form = await proposeChange(page, eventId, from, change);
  await expect(form).toBeHidden();
}

async function accept(page, eventId, value) {
  const proposals = await openProposals(page, eventId);
  await expectServerOk(row(proposals, value).getByRole('button', { name: 'Accept proposal' })
    .or(proposals.getByRole('button', { name: 'Accept proposal' })).first(), '/shadow_attributes/accept/');
}

test('Proposal accept – value change', async ({ page, api, ts, cleanup }) => {
  blockedBy(PROPOSAL_BUG);
  const [from, to] = [uniqueIp(ts), uniqueIp(Number(ts) + 1)];
  const event = await eventWithIps(api, cleanup, `QA accept value ${ts}`, [from], { publish: true });
  await propose(page, event.id, from, { value: to });
  await accept(page, event.id, to);

  await openEvent(page, event.id);
  const attributes = await openTab(page, 'Attributes');
  await expect(row(attributes, to)).toBeVisible();
  await expect(row(attributes, from)).toHaveCount(0);
  expect(await api.proposalsOf(event.id)).toHaveLength(0);
  expect((await api.getEvent(event.id)).published).toBe(false);
  await expectScreen(row(attributes, to), 'proposal-accept-value.png');
});

test('Proposal accept – deletion', async ({ page, api, ts, cleanup }) => {
  blockedBy(PROPOSAL_BUG);
  const value = uniqueIp(ts);
  const event = await eventWithIps(api, cleanup, `QA accept delete ${ts}`, [value]);
  await propose(page, event.id, value, { deletion: true });
  await accept(page, event.id, value);

  expect((await api.getEvent(event.id)).Attribute.filter((a) => a.value === value && !a.deleted))
    .toHaveLength(0);
  expect(await api.proposalsOf(event.id)).toHaveLength(0);
  await expectScreen(page.getByRole('heading', { level: 1 }), 'proposal-accept-delete.png');
});

test('Proposal discard', async ({ page, api, ts, cleanup }) => {
  blockedBy(PROPOSAL_BUG);
  const [from, to] = [uniqueIp(ts), uniqueIp(Number(ts) + 1)];
  const event = await eventWithIps(api, cleanup, `QA discard ${ts}`, [from]);
  await propose(page, event.id, from, { value: to });

  const proposals = await openProposals(page, event.id);
  await proposals.getByRole('button', { name: 'Discard proposal' }).first().click();
  await expectServerOk(dialog(page).getByRole('button', { name: 'Discard', exact: true }),
    '/shadow_attributes/discard/');
  await expect(page.getByText('Proposal discarded.')).toBeVisible();
  await openEvent(page, event.id);
  await expect(row(await openTab(page, 'Attributes'), from)).toBeVisible();
  expect(await api.proposalsOf(event.id)).toHaveLength(0);
  await expectScreen(page.getByRole('heading', { level: 1 }), 'proposal-discard.png');
});

test('Proposal accept – twice', async ({ page, pageAs, api, ts, cleanup }) => {
  blockedBy(PROPOSAL_BUG);
  const [from, to] = [uniqueIp(ts), uniqueIp(Number(ts) + 1)];
  const event = await eventWithIps(api, cleanup, `QA accept twice ${ts}`, [from]);
  await propose(page, event.id, from, { value: to });

  const second = await pageAs('siteAdmin');
  const secondProposals = await openProposals(second, event.id);
  await accept(page, event.id, to);
  const button = secondProposals.getByRole('button', { name: 'Accept proposal' }).first();
  await button.click();
  await expect(second.getByText(/does not exist|not found|already/i).first()).toBeVisible();
  await expect(second.getByText('Proposed change accepted.')).toHaveCount(0);
  const values = (await api.getEvent(event.id)).Attribute.filter((a) => a.value === to && !a.deleted);
  expect(values).toHaveLength(1);
});

test('Proposal accept – attribute deleted meanwhile', async ({ page, api, ts, cleanup }) => {
  blockedBy(PROPOSAL_BUG);
  const [from, to] = [uniqueIp(ts), uniqueIp(Number(ts) + 1)];
  const event = await eventWithIps(api, cleanup, `QA accept deleted attribute ${ts}`, [from]);
  await propose(page, event.id, from, { value: to });
  const proposals = await openProposals(page, event.id);
  const attribute = (await api.getEvent(event.id)).Attribute.find((a) => a.value === from);
  await api.post(`/attributes/delete/${attribute.id}/1`);

  await expectServerOk(proposals.getByRole('button', { name: 'Accept proposal' }).first(),
    '/shadow_attributes/accept/');
  await expect(page.getByText(/does not exist|not found|deleted/i).first()).toBeVisible();
  await expectNoErrorPage(page);
  const raw = await api.raw('GET', `/attributes/restSearch/value:${to}`);
  expect(raw.text).not.toContain(to);
});

test('Proposal accept – several at once', async ({ page, api, ts, cleanup }) => {
  const ips = [0, 1, 2, 3].map((i) => uniqueIp(Number(ts) + i));
  const event = await eventWithIps(api, cleanup, `QA accept all ${ts}`, [ips[0], ips[1]]);
  await propose(page, event.id, ips[0], { value: ips[2] });
  await propose(page, event.id, ips[1], { value: ips[3] });

  const proposals = await openProposals(page, event.id);
  await expect(proposals.getByRole('button', { name: 'Accept proposal' })).toHaveCount(2);
  blockedBy('Missing feature: the Overmind event page has no "Accept all" for its proposals');
  await expect(page.getByRole('button', { name: /Accept all/i })
    .or(page.getByRole('link', { name: /Accept all/i })).first()).toBeVisible({ timeout: 3_000 });
});
