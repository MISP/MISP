<?php
/*
 * The counts an event preview index asked for (Feeds and Servers
 * preview_index.ctp), each drawn by the events index's count cell for
 * preview-index-counts.js to put in its row.
 *
 *   $counts  array  row key => attribute_count, object_count; null when unread
 */
foreach ($counts as $key => $eventCounts): ?>
<div data-key="<?= h($key) ?>"<?= $eventCounts === null ? ' data-failed' : '' ?>>
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
