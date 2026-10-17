<?php
/*
 * The analyst-data thread attached to a given MISP object, through the shared
 * Elements/AnalystData/thread renderer.
 *
 * Two readers, told apart by `?embedded=1`:
 *   - openModal, from the analyst-data count badges in the index tables: the
 *     fragment is the whole modal, so it draws the chrome and the gutters.
 *   - a card that fetches the thread into its own body (the event view's
 *     analyst data card): the chrome would be a second header inside a card
 *     that already has one, and the card clamps the height with a peek.
 */
$embedded = !empty($this->request->query['embedded']);
$thread = $this->element('AnalystData/thread', [
    'analystData' => $analystData,
    'objectType'  => $objectType,
    'objectUuid'  => $objectUuid,
    'peek'        => $embedded,
]);

if ($embedded) {
    echo $thread;
    return;
}
echo $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'analystData',
    'eyebrow' => __('Analyst Data'),
    'title' => $objectType,
    'titleIcon' => 'fas fa-clipboard-list',
    'description' => $objectUuid,
    'descriptionClass' => 'font-monospace',
    'close' => true,
]);
?>
<div class="container-fluid px-3 py-2"><?= $thread ?></div>
