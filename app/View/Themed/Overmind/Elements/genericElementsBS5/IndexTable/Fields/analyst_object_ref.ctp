<?php
/*
 * Renders a type badge + the FULL referenced object UUID as a link. Shared by the
 * Analyst Data indexes for both the parent "Target" and the "Related object".
 *
 * Config:
 *   $field['type_path'] — Hash path to the object type (e.g. 'Note.object_type')
 *   $field['uuid_path'] — Hash path to the object uuid (e.g. 'Note.object_uuid')
 */
$type = (string)Hash::get($row, $field['type_path'] ?? '');
$uuid = (string)Hash::get($row, $field['uuid_path'] ?? '');

if ($uuid === '') {
    echo '<span class="text-muted">&mdash;</span>';
    return;
}

if (in_array($type, ['Note', 'Opinion', 'Relationship'], true)) {
    $url = $baseurl . '/analystData/view/' . $type . '/' . $uuid;
} elseif ($type === 'Event') {
    $url = $baseurl . '/events/view2/' . $uuid;
} else {
    $url = $baseurl . '/' . Inflector::tableize($type) . '/view/' . $uuid;
}
?>
<div class="d-flex align-items-center gap-2 flex-wrap">
    <?php if ($type !== ''): ?>
        <span class="badge bg-secondary-subtle text-secondary-emphasis text-uppercase">
            <?= h($type) ?>
        </span>
    <?php endif; ?>
    <a class="text-decoration-none font-monospace small text-body-primary text-break"
       href="<?= h($url) ?>" title="<?= h($uuid) ?>">
        <?= h($uuid) ?>
    </a>
</div>
