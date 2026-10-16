<?php
App::uses('AnalystData', 'Model');
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
/*
 * Renders a type badge + the FULL referenced object UUID as a link. Shared by the
 * Analyst Data indexes for both the parent "Target" and the "Related object".
 *
 * Config:
 *   $field['type_path']   — Hash path to the object type (e.g. 'Note.object_type')
 *   $field['uuid_path']   — Hash path to the object uuid (e.g. 'Note.object_uuid')
 *   $field['sha256_path'] — Hash path to the SHA-256 naming a value target
 *
 * $analystTargetExists (address => true), set by the controller, says which targets
 * this instance still holds. Without it every uuid is linked, as before.
 * $analystTargets (SHA-256 => description) holds the text of the values the user can see.
 */
$type = (string)Hash::get($row, $field['type_path'] ?? '');
$isValue = in_array($type, AnalystData::SHA256_TARGETS, true);
$uuid = (string)Hash::get($row, $field[$isValue ? 'sha256_path' : 'uuid_path'] ?? '');

if ($uuid === '') {
    echo '<span class="text-muted">&mdash;</span>';
    return;
}

$described = $isValue ? ($analystTargets[strtolower($uuid)] ?? null) : null;
$valueText = $described['value'] ?? null;
if ($isValue) {
    $url = $valueText === null ? '' : $baseurl . '/values/view/' . ValueUrlTool::address($valueText);
} elseif (in_array($type, ['Note', 'Opinion', 'Relationship'], true)) {
    $url = $baseurl . '/analystData/view/' . $type . '/' . $uuid;
} elseif ($type === 'Event') {
    $url = $baseurl . '/events/view/' . $uuid;
} else {
    $url = $baseurl . '/' . Inflector::tableize($type) . '/view/' . $uuid;
}

$resolves = $isValue ? $valueText !== null : (!isset($analystTargetExists) || !empty($analystTargetExists[$uuid]));
$missingTitle = __(
    'This %s is not on this instance, or is not visible to you.',
    $type !== '' ? $type : __('object')
);
?>
<div class="d-flex align-items-center gap-2 flex-wrap">
    <?php if ($type !== ''): ?>
        <span class="badge bg-secondary-subtle text-secondary-emphasis text-uppercase">
            <?= h($isValue ? __('Value') : $type) ?>
        </span>
    <?php endif; ?>
    <?php if ($resolves && $isValue): ?>
        <a class="text-decoration-none font-monospace small text-body-primary text-break"
           href="<?= h($url) ?>" title="<?= h($uuid) ?>">
            <?= h($described['label']) ?>
        </a>
    <?php elseif ($resolves): ?>
        <a class="text-decoration-none font-monospace small text-body-primary text-break"
           href="<?= h($url) ?>" title="<?= h($uuid) ?>">
            <?= h($uuid) ?>
        </a>
    <?php elseif ($isValue): ?>
        <span class="font-monospace small text-body-secondary text-break"
              title="<?= h(__('This value could not be resolved, so it is shown by the SHA-256 of its text.')) ?>">
            <?= h($uuid) ?>
        </span>
    <?php else: ?>
        <span class="font-monospace small text-muted text-break text-decoration-line-through"
              title="<?= h($missingTitle) ?>">
            <?= h($uuid) ?>
        </span>
    <?php endif; ?>
</div>
