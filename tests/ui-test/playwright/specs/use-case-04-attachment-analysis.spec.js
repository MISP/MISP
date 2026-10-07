// ../../use-case/04-attachment-analysis.md
const crypto = require('crypto');
const fs = require('fs');
const {
  test, expect, expectDialogSaved, blockedBy, openEvent, openTab, row, pick, dialog,
  expectScreen,
  eventCard,
} = require('../helpers');

test.use({ role: 'orgAdminA' });

test('Use case 4 – Analyse the email attachment', async ({ page, apiAs, api, ts, cleanup }, testInfo) => {
  blockedBy('Bug 4 (saving an object is black-holed when the user can see no sharing group: the empty Sharing group field breaks the form token)');
  const info = `Fake-Parcel attachment ${ts}`;
  const event = await apiAs('orgAdminA').createEvent({ info });
  cleanup(() => api.deleteEventsByInfo(info));

  const content = Buffer.from(`QA fake parcel attachment ${ts}`);

  await test.step('Phase 1 – Store the attachment safely', async () => {
    await openEvent(page, event.id);
    await page.getByRole('link', { name: 'Add Attachment' }).click();
    const form = dialog(page);
    await form.locator('input[type=file]').setInputFiles({
      name: 'Delivery_Note.txt',
      mimeType: 'text/plain',
      buffer: content,
    });
    await form.getByRole('checkbox', { name: /^Malware Sample/ }).check();
    await form.getByRole('button', { name: 'Upload' }).click();
    // A malware sample is stored as a "file" object with its hashes.
    const objects = await openTab(page, 'Objects');
    await objects.getByRole('button', { name: /^file file .*Delivery_Note\.txt/ }).click();
    const md5 = crypto.createHash('md5').update(content).digest('hex');
    await expect(row(objects, `Delivery_Note.txt|${md5}`)).toContainText('malware-sample');
    await expect(row(objects, md5)).toContainText('md5');
    await expect(row(objects, crypto.createHash('sha1').update(content).digest('hex'))).toContainText('sha1');
    await expect(row(objects, crypto.createHash('sha256').update(content).digest('hex')))
      .toContainText('sha256');
  });

  await test.step('Phase 3 – Check the download is protected', async () => {
    await openEvent(page, event.id);
    const attachments = page.getByRole('tabpanel').getByRole('row').filter({ hasText: 'Delivery_Note.txt' });
    await expect(attachments).toContainText('application/zip');
    const download = page.waitForEvent('download');
    await attachments.getByRole('link', { name: 'Download' }).click();
    const file = testInfo.outputPath('sample.zip');
    await (await download).saveAs(file);
    const bytes = fs.readFileSync(file);
    expect(bytes.subarray(0, 2).toString()).toBe('PK');
    // General purpose flag, bit 0: the zip entry is encrypted.
    expect(bytes.readUInt16LE(6) & 1).toBe(1);
  });

  await test.step('Phase 2 – Record the server contacted by the attachment', async () => {
    await openTab(page, 'General');
    await page.getByRole('link', { name: 'Add Object' }).click();
    await pick(dialog(page).getByRole('combobox', { name: /Template/ }), 'domain-ip', 'Domain-ip');
    await dialog(page).getByRole('button', { name: 'Next' }).click();
    const form = dialog(page);
    await form.getByRole('button', { name: /^Domain domain/ }).click();
    await form.getByRole('button', { name: /^Ip ip-dst/ }).click();
    await form.locator('.attribute_row[data-object-relation="domain"] textarea.Attribute_value')
      .fill('update.parcel-tracking.example');
    await form.locator('.attribute_row[data-object-relation="ip"] textarea.Attribute_value')
      .fill('203.0.113.50');
    await form.getByRole('textbox', { name: 'Comment', exact: true }).fill('C2 contacted by Delivery_Note.txt');
    await form.getByRole('button', { name: 'Review', exact: true }).filter({ visible: true }).first().click();
    await form.getByRole('button', { name: 'Add Object' }).click();
    await expectDialogSaved(page);
  });

  const saved = await api.getEvent(event.id);
  const object = saved.Object.find((o) => o.name === 'domain-ip');
  expect(object.comment).toBe('C2 contacted by Delivery_Note.txt');
  await openEvent(page, event.id);
    await expectScreen(eventCard(page, 'attachment'), 'use-case-4-attachments.png');
});
