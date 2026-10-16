<?php
/**
 * An event reference on one line.
 *
 * `Fields/event` renders `Badges/event`, which is a bordered block with
 * a header strip over the event's info — the right thing on a page
 * whose subject is the event, and 95px of row height on a card whose
 * subject is a value. The Overview's occurrence preview draws eight
 * rows to say *where this value turns up*; at the badge's height those
 * eight rows are most of the tab.
 *
 * Same link, same target, same two facts, on one line: the id as the
 * anchor and the info beside it, truncated rather than wrapped so a
 * long event title cannot decide the table's row height. The
 * Occurrences tab keeps the badge — it has the width and the reader
 * came there for the rows.
 *
 * Expected:
 *   $field['data_path'] "Event.id" or "Event.id, Event.info"
 *   $field['url']       URL template; %id% / %event_id% take the id
 */
$paths = array_map('trim', explode(',', $field['data_path']));
$id = Hash::get($row, $paths[0]);

if (empty($id)) {
    return;
}

$name = isset($paths[1]) ? Hash::get($row, $paths[1]) : null;
$url = empty($field['url'])
    ? $baseurl . '/events/view/' . $id
    : str_replace(array('%id%', '%event_id%'), $id, $field['url']);
?>
<div class="vp-event-ref">
    <a href="<?= h($url) ?>" class="vp-event-ref-id" target="_blank"
       title="<?= h(sprintf(__('Open event %s'), $id)) ?>">
        <span class="misp-icon misp-icon-event misp-simple"></span>
        <span><?= sprintf('#%s', h($id)) ?></span>
    </a>
    <?php if (!empty($name)): ?>
        <span class="vp-event-ref-info" title="<?= h($name) ?>">
            <?= h($name) ?>
        </span>
    <?php endif; ?>
</div>
