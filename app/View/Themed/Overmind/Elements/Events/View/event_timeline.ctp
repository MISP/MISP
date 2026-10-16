<?php
/**
 * The Timeline tab: filled by event-seen-timeline.js from
 * events/viewEventTimeline the first time the tab is shown.
 */
$eventId = (int)($data['Event']['id'] ?? 0);
$suffix = $extensionSuffix ?? '';
?>
<div class="card shadow-sm mb-3 etl" data-timeline
     data-url="<?= h($baseurl . '/events/viewEventTimeline/' . $eventId . $suffix . '.json') ?>">
    <div class="p-5">
        <?= $this->element('genericElementsBS5/loader', ['label' => __('Loading the timeline…')]) ?>
    </div>
</div>
