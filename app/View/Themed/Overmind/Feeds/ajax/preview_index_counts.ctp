<?php
/*
 * The counts FeedsController::previewIndexCounts() read, each drawn by the
 * events index's count cell for Feeds/preview_index.ctp to put in its row.
 */
foreach ($counts as $uuid => $eventCounts): ?>
<div data-uuid="<?= h($uuid) ?>"<?= $eventCounts === null ? ' data-failed' : '' ?>>
    <?php if ($eventCounts !== null): ?>
        <?php foreach (['attributes', 'objects'] as $count): ?>
            <span data-count="<?= $count ?>"><?= $this->element('genericElementsBS5/IndexTable/Fields/event_count', [
                'row' => ['Event' => $eventCounts],
                'field' => ['count' => $count],
            ]) ?></span>
        <?php endforeach; ?>
    <?php endif; ?>
</div>
<?php endforeach;
