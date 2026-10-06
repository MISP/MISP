// ../../attribute/add/attachment.md
const crypto = require('crypto');
const fs = require('fs');
const {
  test, expect, expectNoErrorPage, expectScreen, blockedBy, openEvent, openTab, row, dialog, eventCard,
} = require('../helpers');

test.use({ role: 'siteAdmin' });

async function upload(page, { name, content, malware }) {
  await page.getByRole('link', { name: 'Add Attachment' }).click();
  const form = dialog(page);
  if (name) await form.locator('input[type=file]').setInputFiles({ name, mimeType: 'application/octet-stream', buffer: content });
  const sample = form.getByRole('checkbox', { name: /^Malware Sample/ });
  if (malware) await sample.check(); else await sample.uncheck();
  await form.getByRole('button', { name: 'Upload' }).click();
  return form;
}

// Downloads the attachment `name` from the "Event Attachments" panel.
async function download(page, eventId, name, testInfo) {
  await openEvent(page, eventId);
  const file = eventCard(page, 'attachment').getByRole('row').filter({ hasText: name });
  const pending = page.waitForEvent('download');
  await file.getByRole('link', { name: 'Download' }).click();
  const path = testInfo.outputPath(`download-${name}`);
  await (await pending).saveAs(path);
  return fs.readFileSync(path);
}

test('Attachment – upload a file', async ({ page, api, ts, cleanup }, testInfo) => {
  const event = await api.createEvent({ info: `QA attachment ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));
  const content = Buffer.from(`QA attachment ${ts}`);

  await openEvent(page, event.id);
  await upload(page, { name: 'qa.txt', content });
  const r = row(await openTab(page, 'Attributes'), 'qa.txt');
  await expect(r.getByRole('cell', { name: 'attachment', exact: true })).toBeVisible();

  expect((await download(page, event.id, 'qa.txt', testInfo)).equals(content)).toBe(true);
  await expectScreen(eventCard(page, 'attachment'), 'attribute-attachment-upload.png');
});

test('Attachment – malware sample', async ({ page, api, ts, cleanup }, testInfo) => {
  const event = await api.createEvent({ info: `QA malware sample ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));
  const content = Buffer.from(`QA sample ${ts}`);
  const hash = (alg) => crypto.createHash(alg).update(content).digest('hex');

  await openEvent(page, event.id);
  await upload(page, { name: 'qa-sample.bin', content, malware: true });
  const objects = await openTab(page, 'Objects');
  await objects.getByRole('button', { name: /^file file .*qa-sample\.bin/ }).click();
  await expect(row(objects, `qa-sample.bin|${hash('md5')}`)).toContainText('malware-sample');
  for (const alg of ['md5', 'sha1', 'sha256']) await expect(row(objects, hash(alg))).toContainText(alg);

  const zip = await download(page, event.id, 'qa-sample.bin', testInfo);
  expect(zip.subarray(0, 2).toString()).toBe('PK');
  expect(zip.readUInt16LE(6) & 1, 'the zip entry is encrypted').toBe(1);
  await expectScreen(eventCard(page, 'attachment'), 'attribute-attachment-malware.png');
});

test('Attachment – no file selected', async ({ page, api, ts, cleanup }) => {
  blockedBy('New bug: Upload without a file closes the form and reloads the event with no message');
  const event = await api.createEvent({ info: `QA attachment empty ${ts}` });
  cleanup(() => api.deleteEventsByInfo(event.info));
  const message = /select.*file|file.*required|no file/i;

  await openEvent(page, event.id);
  const form = await upload(page, {});
  await Promise.race([form.getByText(message).first().waitFor(), form.waitFor({ state: 'hidden' })]);

  await expectNoErrorPage(page);
  expect((await api.getEvent(event.id)).Attribute).toHaveLength(0);
  expect(await form.isVisible(), 'MISP closed the form and showed no message').toBe(true);
  await expect(form.getByText(message).first()).toBeVisible();
  await expectScreen(form, 'attribute-attachment-no-file.png');
});
