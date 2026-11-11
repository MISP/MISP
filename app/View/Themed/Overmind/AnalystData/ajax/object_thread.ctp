<?php
/*
 * The analyst-data thread attached to a given MISP object. Delegates to the
 * shared Elements/AnalystData/thread renderer (the full-page analystData/view
 * reuses the same one).
 *
 * Two readers, told apart by `?embedded=1`:
 *   - openModal, from the analyst-data count badges in the index tables: the
 *     fragment is the whole modal, so it draws the chrome and the gutters.
 *   - a card that fetches the thread into its own body (the event view's
 *     analyst data card): the chrome would be a second header inside a card
 *     that already has one, and the gutters a second set of padding.
 */
$embedded = !empty($this->request->query['embedded']);

echo $this->element('AnalystData/thread', [
    'analystData'     => $analystData,
    'objectType'      => $objectType,
    'objectUuid'      => $objectUuid,
    'showModalHeader' => !$embedded,
    'bodyClass'       => $embedded ? 'p-3' : 'container-fluid px-4 py-4',
]);
