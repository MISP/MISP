<?php
/**
 * Overmind BS5 — delete (detach) confirmation for a signing key.
 *
 * Rendered layout-less as a modal fragment on the GET of
 * CryptographicKeysController::delete (theme === 'Overmind' branch). The form
 * POSTs back to the same delete URL; the id travels in the URL, so the
 * hidden 'id' field is unused but harmless. The ownership gate stays in the
 * controller's beforeDelete on the POST path.
 */
echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Detach signing key'),
    'model' => 'CryptographicKey',
    'url' => $baseurl . '/cryptographicKeys/delete/' . h($id),
    'message' => __('Are you sure you want to detach cryptographic key #%s from the event? This key will no longer be used to sign and validate this event.', h($id))
]);
