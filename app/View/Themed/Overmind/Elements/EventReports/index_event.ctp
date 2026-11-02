<?php
/**
 * The event a report belongs to, in the reports indexes: its id and its title,
 * as the objects index gives it.
 *
 * Parameters:
 *   row  array  one row of the index
 *
 * Read from the view: $baseurl.
 */
if (empty($row['Event']['id'])) {
    return;
}
$id = (int)$row['Event']['id'];
$info = (string)($row['Event']['info'] ?? '');
?>
<a class="er-event" href="<?= h($baseurl . '/events/view/' . $id) ?>" title="<?= h($info) ?>">
    <span class="er-event-id">#<?= $id ?></span>
    <span class="er-event-info"><?= h($info) ?></span>
</a>
