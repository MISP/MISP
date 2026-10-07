// ../../proposal/cross-org/cross-org.md
const {
  test, expect, expectNoErrorPage, expectServerOk, blockedBy, expectScreen, openEvent, openTab, row,
  dialog, proposeChange, openProposals, PROPOSAL_BUG, uniqueIp,
} = require('../helpers');

// "QA roles community event": an event of ADMIN shared with the community.
async function communityEvent(api, apiAs, cleanup, ts, distribution = 'community') {
  const [value, proposed] = [uniqueIp(ts), uniqueIp(Number(ts) + 1)];
  const info = `QA roles ${distribution} event ${ts}`;
  cleanup(() => api.deleteEventsByInfo(info));
  const event = await apiAs('orgAdminA').createEvent({
    info, distribution, attributes: [{ type: 'ip-dst', category: 'Network activity', value }],
  });
  const attribute = (await api.getEvent(event.id)).Attribute[0];
  return { event, info, value, proposed, attribute };
}

test.describe('as user of QA-Org-B', () => {
  test.use({ role: 'userB' });

  test('Proposal – from another organisation', async ({ page, api, apiAs, ts, cleanup }) => {
    const { event, value, proposed } = await communityEvent(api, apiAs, cleanup, ts);
    const form = await proposeChange(page, event.id, value, { value: proposed });
    await expect(form).toBeHidden();
    await expectNoErrorPage(page);
    const proposals = await api.proposalsOf(event.id);
    expect(proposals.map((p) => p.value)).toEqual([proposed]);
    await openEvent(page, event.id);
    const attributes = await openTab(page, 'Attributes');
    await expect(row(attributes, value)).toBeVisible();
    await expectScreen(row(attributes, value), 'proposal-cross-org-create.png');
  });

  test('Proposal – proposer cannot accept', async ({ page, api, apiAs, ts, cleanup }) => {
    const { event, value, proposed, attribute } = await communityEvent(api, apiAs, cleanup, ts);
    await apiAs('userB').proposeEdit(attribute.id, proposed);

    const proposals = await openProposals(page, event.id);
    const acceptButton = proposals.getByRole('button', { name: 'Accept proposal' });
    if (await acceptButton.count()) {
      await acceptButton.first().click();
      await expect(page.getByText(/not authorised|not allowed|permission/i).first()).toBeVisible();
    }
    expect((await api.getEvent(event.id)).Attribute.map((a) => a.value)).toEqual([value]);
    await expectNoErrorPage(page);
    await expectScreen(page.getByRole('heading', { level: 1 }), 'proposal-cross-org-self-accept.png');
  });

  test('Proposal – event not visible', async ({ page, api, apiAs, ts, cleanup }) => {
    const { event, value, proposed, attribute } = await communityEvent(api, apiAs, cleanup, ts, 'org');
    const res = await page.goto(`/events/view2/${event.id}`);
    await expect(page.getByText(value)).toHaveCount(0);
    await expect(page.getByText(/Invalid event|not found/i).first()).toBeVisible();
    expect(res.status()).toBeGreaterThanOrEqual(400);
    const refused = await apiAs('userB').raw('POST', `/shadow_attributes/edit/${attribute.id}`,
      { ShadowAttribute: { value: proposed } });
    expect(refused.status).toBe(404);
    expect(await api.proposalsOf(event.id)).toHaveLength(0);
    await expectScreen(page.getByText(/Invalid event|not found/i).first(), 'proposal-cross-org-not-visible.png');
  });
});

test.describe('as org-admin of ADMIN', () => {
  test.use({ role: 'orgAdminA' });

  test('Proposal – listed for the event organisation', async ({ page, pageAs, api, apiAs, ts, cleanup }) => {
    const { info, proposed, attribute } = await communityEvent(api, apiAs, cleanup, ts);
    await apiAs('userB').proposeEdit(attribute.id, proposed);

    await page.goto('/shadow_attributes/index/all:0');
    const listed = row(page.getByRole('main'), proposed);
    await expect(listed).toContainText(info);
    await expect(listed).toContainText('QA-Org-B');
    await expectScreen(listed, 'proposal-cross-org-index.png');

    const proposer = await pageAs('userB');
    await proposer.goto('/shadow_attributes/index/all:0');
    await expect(row(proposer.getByRole('main'), proposed)).toHaveCount(0);
  });

  test('Proposal – discard by the event organisation', async ({ page, api, apiAs, ts, cleanup }) => {
    blockedBy(PROPOSAL_BUG);
    const { event } = await communityEvent(api, apiAs, cleanup, ts);
    await apiAs('userB').post(`/shadow_attributes/add/${event.id}`, {
      ShadowAttribute: { type: 'domain', category: 'Network activity', value: `qa-proposed-by-b-${ts}.example` },
    });

    const proposals = await openProposals(page, event.id);
    await row(proposals, `qa-proposed-by-b-${ts}.example`).getByRole('button', { name: 'Discard proposal' }).click();
    await expectServerOk(dialog(page).getByRole('button', { name: 'Discard', exact: true }),
      '/shadow_attributes/discard/');
    await expect(page.getByText('Proposal discarded.')).toBeVisible();
    expect((await api.getEvent(event.id)).Attribute.map((a) => a.value))
      .not.toContain(`qa-proposed-by-b-${ts}.example`);
  });
});

test.describe('as user of ADMIN', () => {
  test.use({ role: 'userA' });

  test('Proposal – accepted by a user without publish right', async ({ page, api, apiAs, ts, cleanup }) => {
    const { event, value, proposed, attribute } = await communityEvent(api, apiAs, cleanup, ts);
    await apiAs('userB').proposeEdit(attribute.id, proposed);

    const proposals = await openProposals(page, event.id);
    const acceptButton = proposals.getByRole('button', { name: 'Accept proposal' });
    // The rule in ShadowAttributesController: only publishing users handle proposals.
    if (await acceptButton.count()) {
      blockedBy(PROPOSAL_BUG);
      await expectServerOk(acceptButton.first(), '/shadow_attributes/accept/');
      await expect(page.getByText(/not authorised|not allowed|permission/i).first()).toBeVisible();
    }
    expect((await api.getEvent(event.id)).Attribute.map((a) => a.value)).toEqual([value]);
    await expectScreen(page.getByRole('heading', { level: 1 }), 'proposal-cross-org-accept-user.png');
  });
});
