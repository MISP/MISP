<?php
/*
 * Renders a type badge + the FULL referenced object UUID as a link. Shared by the
 * Analyst Data indexes for both the parent "Target" and the "Related object".
 *
 * Config:
 *   $field['type_path'] — Hash path to the object type (e.g. 'Note.object_type')
 *   $field['uuid_path'] — Hash path to the object uuid (e.g. 'Note.object_uuid')
 *
 * $analystTargetExists (uuid => true), set by the controller, says which targets
 * this instance still holds. Without it every uuid is linked, as before.
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

$resolves = !isset($analystTargetExists) || !empty($analystTargetExists[$uuid]);
$missingTitle = __(
    'This %s is not on this instance, or is not visible to you.',
    $type !== '' ? $type : __('object')
);
?>
<div class="d-flex align-items-center gap-2 flex-wrap">
    <?php if ($type !== ''): ?>
        <span class="badge bg-secondary-subtle text-secondary-emphasis text-uppercase">
            <?= h($type) ?>
        </span>
    <?php endif; ?>
    <?php if ($resolves): ?>
        <a class="text-decoration-none font-monospace small text-body-primary text-break"
           href="<?= h($url) ?>" title="<?= h($uuid) ?>">
            <?= h($uuid) ?>
        </a>
    <?php else: ?>
        <span class="font-monospace small text-muted text-break text-decoration-line-through"
              title="<?= h($missingTitle) ?>">
            <?= h($uuid) ?>
        </span>
    <?php endif; ?>
</div>
