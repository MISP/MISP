<?php
/*
 * Debug-mode cell for the workflow indexes.
 * A lit bug when debug mode is on, a struck-through and muted one when it is off 
 *
 * Optional $field['empty_text'] renders a muted hint in that case.
 */
$raw = Hash::get($row, $field['data_path']);
$isCard = isset($viewMode) && $viewMode === 'card';

if ($raw === null) {
    if (!empty($field['empty_text'])) {
        printf('<span class="text-muted small fst-italic">%s</span>', h($field['empty_text']));
    }
    return;
}

$on = !empty($raw);
$label = $on ? __('Debug on') : __('Debug off');
$title = $on
    ? __('Debug mode is on: every node sends its data to Plugin.Workflow_debug_url')
    : __('Debug mode is off');
?>
<?php if ($isCard): ?>
    <span class="badge rounded-pill d-inline-flex align-items-center gap-1 <?= $on ? 'text-bg-warning' : 'text-bg-secondary' ?>"
          title="<?= h($title) ?>">
        <i class="fas <?= $on ? 'fa-bug' : 'fa-bug-slash' ?>"></i><?= h($label) ?>
    </span>
<?php else: ?>
    <i class="fas <?= $on ? 'fa-bug text-warning' : 'fa-bug-slash text-muted opacity-50' ?>"
       style="font-size:1.1em;"
       role="img"
       title="<?= h($title) ?>"
       aria-label="<?= h($label) ?>"></i>
<?php endif; ?>
