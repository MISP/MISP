// ../../../user-workflow/collaboration.md
const {
  test, expect, expectNoErrorPage, blockedBy, openEvent, openTab, row, rowAction, pick, dialog,
} = require('../../helpers');

test.use({ role: 'userB' });

const PROPOSAL_BUG = 'New bug: "Accept proposal" / "Discard proposal" on the event page are '
  + 'black-holed (HTTP 400, "\'_Token\' was not found in request data")';

async function proposeChange(page, eventId, from, to) {
  await openEvent(page, eventId);
  const attributes = await openTab(page, 'Attributes');
  await rowAction(row(attributes, from), 'Propose change');
  const form = dialog(page);
  await expect(form.getByRole('heading', { name: 'Propose a change' })).toBeVisible();
  await form.getByRole('textbox').first().fill(to);
  await form.getByRole('button', { name: 'Submit proposal' }).click();
  await expect(dialog(page)).toHaveCount(0);
}

// The owner's view of the proposals of one event (Attributes tab > Proposals).
async function openProposals(page, eventId) {
  await openEvent(page, eventId);
  const attributes = await openTab(page, 'Attributes');
  await attributes.getByRole('link', { name: /^Proposals/ }).click();
  return page.getByRole('tabpanel').filter({ visible: true });
}

test('Propose a change and accept it', async ({ page, pageAs, apiAs, api, ts, cleanup }) => {
  blockedBy(PROPOSAL_BUG);
  const info = `QA wf proposal ${ts}`;
  const event = await apiAs('orgAdminA').createEvent({
    info,
    distribution: 'community',
    attributes: [{ type: 'ip-dst', category: 'Network activity', value: '203.0.113.90' }],
  });
  cleanup(() => api.deleteEventsByInfo(info));

  await test.step('as user of QA-Org-B: propose 203.0.113.91', async () => {
    await proposeChange(page, event.id, '203.0.113.90', '203.0.113.91');
    const attributes = await openTab(page, 'Attributes');
    await expect(row(attributes, '203.0.113.90')).toBeVisible();
  });

  const owner = await pageAs('orgAdminA');
  await test.step('as org-admin of ADMIN: find and accept the proposal', async () => {
    await owner.goto('/shadow_attributes/index/all:0');
    await expect(row(owner.getByRole('main'), '203.0.113.91').filter({ hasText: info }))
      .toContainText('QA-Org-B');
    const proposals = await openProposals(owner, event.id);
    await proposals.getByRole('button', { name: 'Accept proposal' }).click();
    await expectNoErrorPage(owner);
    await expect(owner.getByText('Could not accept the proposal.')).toHaveCount(0);
  });

  await openEvent(owner, event.id);
  const attributes = await openTab(owner, 'Attributes');
  await expect(row(attributes, '203.0.113.91')).toBeVisible();
  await expect(row(attributes, '203.0.113.90')).toHaveCount(0);
  await expect(attributes.getByRole('link', { name: /^Proposals/ })).not.toContainText(/\(\d+\)/);
});

test('Propose a change and discard it', async ({ page, pageAs, apiAs, api, ts, cleanup }) => {
  blockedBy(PROPOSAL_BUG);
  const info = `QA wf proposal discard ${ts}`;
  const event = await apiAs('orgAdminA').createEvent({
    info,
    distribution: 'community',
    attributes: [{ type: 'ip-dst', category: 'Network activity', value: '203.0.113.92' }],
  });
  cleanup(() => api.deleteEventsByInfo(info));

  await proposeChange(page, event.id, '203.0.113.92', '203.0.113.93');

  const owner = await pageAs('orgAdminA');
  const proposals = await openProposals(owner, event.id);
  await proposals.getByRole('button', { name: 'Discard proposal' }).click();
  await dialog(owner).getByRole('button', { name: 'Discard', exact: true }).click();

  await expect(owner.getByText('Proposal discarded.')).toBeVisible();
  await openEvent(owner, event.id);
  const attributes = await openTab(owner, 'Attributes');
  await expect(row(attributes, '203.0.113.92')).toBeVisible();
  await expect(attributes.getByRole('link', { name: /^Proposals/ })).not.toContainText(/\(\d+\)/);
  await expectNoErrorPage(owner);
});

test('Propose a new attribute', async ({ page, pageAs, apiAs, api, ts, cleanup }) => {
  blockedBy('Missing feature: Overmind has no button to propose a new attribute on the event '
    + 'of another organisation (only /shadow_attributes/add through the API)');
  const info = `QA wf proposal new ${ts}`;
  const event = await apiAs('orgAdminA').createEvent({ info, distribution: 'community' });
  cleanup(() => api.deleteEventsByInfo(info));

  await openEvent(page, event.id);
  const add = page.getByRole('link', { name: /^(Add|Propose) Attribute/ });
  await expect(add).toBeVisible({ timeout: 5_000 });
  await add.click();
  const form = dialog(page);
  await expect(form.getByRole('heading', { level: 4 })).toContainText(/propos/i);
  await pick(form.locator('.ts-wrapper').first().getByRole('combobox'), 'Network activity');
  await pick(form.locator('.ts-wrapper').nth(1).getByRole('combobox'), 'domain');
  await form.getByRole('textbox', { name: /Enter the indicator value/ }).fill('qa-wf-proposed.example');
  await form.getByRole('button', { name: /propos|Add|Submit/i }).last().click();

  await openEvent(page, event.id);
  let attributes = await openTab(page, 'Attributes');
  await expect(row(attributes, 'qa-wf-proposed.example')).toHaveCount(0);

  const owner = await pageAs('orgAdminA');
  const proposals = await openProposals(owner, event.id);
  await proposals.getByRole('button', { name: 'Accept proposal' }).click();
  await expect(owner.getByText('Could not accept the proposal.')).toHaveCount(0);

  await openEvent(owner, event.id);
  attributes = await openTab(owner, 'Attributes');
  await expect(row(attributes, 'qa-wf-proposed.example')).toBeVisible();
});
