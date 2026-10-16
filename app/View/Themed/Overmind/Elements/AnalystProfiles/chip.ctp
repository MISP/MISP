<?php
/**
 * One setting as a key/value chip, with the value editable in place.
 *
 * The mockup drew these read-only, because a prototype is a reading.
 * The editor's whole purpose is changing one of these numbers, so the
 * chip holds the input rather than sitting beside one.
 *
 * A dashed chip is a key this version has no schema for — kept as
 * written, because dropping it on save would lose an analyst's
 * configuration for a signal a redeploy would bring back.
 *
 * @var array $field
 * @var bool $editable
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');

$id = AnalystProfileFormTool::fieldId($field['path']);
$undeclared = !empty($field['undeclared']);
$title = isset($field['help'])
    ? $field['help']
    : (isset($field['label']) ? $field['label'] : $field['key']);
if ($undeclared) {
    $title = __('This MISP version does not know this setting. It is'
        . ' kept as written.');
}
?>
<span class="kv <?= $undeclared ? 'is-undeclared' : '' ?>"
      title="<?= h($title) ?>">
    <k><label for="<?= h($id) ?>"><?= h($field['key']) ?></label></k>
    <?php if ($editable): ?>
        <?= $this->element('AnalystProfiles/field', array(
            'field' => $field,
            'editable' => true,
        )) ?>
    <?php else: ?>
        <v><?= h($field['value'] === null
            ? '—'
            : (is_bool($field['value'])
                ? ($field['value'] ? 'true' : 'false')
                : $field['value'])) ?></v>
    <?php endif; ?>
</span>
