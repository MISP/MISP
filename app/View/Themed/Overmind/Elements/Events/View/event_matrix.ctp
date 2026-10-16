<?php
/**
 * Rail slot of the overview's galaxy matrix: filled by misp-matrix.js from
 * events/viewEventMatrix, and left empty when the event uses no matrix galaxy.
 */
$eventId = (int)($data['Event']['id'] ?? 0);
$suffix = $extensionSuffix ?? '';
?>
<div data-mx-slot data-url="<?= h($baseurl . '/events/viewEventMatrix/' . $eventId . $suffix) ?>"></div>

<?= $this->element('GalaxyMatrix/modal', [
    'strongLabel' => __('On the event'),
    'lightLabel' => __('Only on indicators'),
]) ?>
