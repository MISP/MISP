<?php
/**
 * The add control as a split button: Add to workspace (In workspace ✓ once
 * the workspace holds the record, opening Show in the dock and Remove from
 * workspace), and a caret offering Add to another collection… and New
 * collection with this…. The caret's menu is drawn by intel-graph-actions.js.
 *
 * @var array $items The records, as IntelGraph.add() takes them, each with a label
 * @var string $variant 'label' (Add to workspace), 'short' (Workspace) or 'icon'
 * @var string $btnClass Button classes (default 'btn-sm btn-outline-analystGraph')
 * @var bool $bare $btnClass is the whole class of the buttons, without .btn
 * @var string $caretClass The caret's classes instead of $btnClass
 * @var string $class Classes added to the group
 * @var string $id The group's id
 * @var string $title Tooltip of the main part (default "Add to workspace")
 * @var bool $stateless Never In workspace ✓: a bulk bar's, whose page keeps
 *                      its items (data-intel-graph-add) in step with the selection
 */
$variant = $variant ?? 'label';
$btnClass = (empty($bare) ? 'btn ' : '') . ($btnClass ?? 'btn-sm btn-outline-analystGraph');
$caretClass = isset($caretClass) ? (empty($bare) ? 'btn ' : '') . $caretClass : $btnClass;
$title = $title ?? __('Add to workspace');
$json = json_encode(array_values($items ?? []));
$labels = [
    'label' => [__('Add to workspace'), __('In workspace ✓')],
    'short' => [__('Workspace'), __('Workspace ✓')],
];
$mainAttrs = [
    'type' => 'button',
    'class' => $btnClass . ' ig-add-main',
    'data-intel-graph-add' => $json,
    'title' => $title,
];
if ($variant === 'icon') {
    $mainAttrs['aria-label'] = $title;
} elseif (empty($stateless)) {
    $mainAttrs['data-intel-graph-label-in'] = $labels[$variant][1];
}
if (!empty($stateless)) {
    $mainAttrs['data-intel-graph-stateless'] = '';
}
$html = '';
foreach ($mainAttrs as $name => $value) {
    $html .= sprintf(' %s="%s"', h($name), h($value));
}
?>
<div class="btn-group ig-add ig-add-<?= h($variant) ?><?= empty($class) ? '' : ' ' . h($class) ?>" role="group" data-intel-graph-split<?= empty($id) ? '' : ' id="' . h($id) . '"' ?>>
    <button<?= $html ?>>
        <i class="misp-icon misp-icon-analyst-graph misp-simple" aria-hidden="true"></i>
        <?php if ($variant === 'icon'): ?>
            <span class="ig-add-check" aria-hidden="true"><i class="fas fa-check"></i></span>
        <?php else: ?>
            <span class="ig-add-lbl"><?= h($labels[$variant][0]) ?></span>
        <?php endif; ?>
    </button>
    <button type="button" class="<?= h($caretClass) ?> dropdown-toggle dropdown-toggle-split ig-add-more"
            data-bs-toggle="dropdown" aria-expanded="false" data-bs-popper-config='{"strategy":"fixed"}'
            title="<?= __('More ways to add') ?>" aria-label="<?= __('More ways to add') ?>"></button>
    <ul class="dropdown-menu dropdown-menu-end ig-add-menu"></ul>
</div>
