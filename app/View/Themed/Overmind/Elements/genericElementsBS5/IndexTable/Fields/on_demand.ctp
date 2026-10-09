<?php
/*
 * on_demand.ctp — a button that queries an endpoint for this row and prints
 * the JSON answer under it; bound by installOnDemandActions().
 *
 * Expected:
 *  $field['data_path']    => the row id, substituted for %id% in the url
 *  $field['url']          => endpoint, answering JSON (a .json url)
 * Optional:
 *  $field['button']       => button label (default 'Run'), '' for icon only
 *  $field['title']        => tooltip, needed when the button has no label
 *  $field['icon']         => FontAwesome name, drawn before the label
 *  $field['text_input']   => POST the value of a text box as `value`
 *  $field['placeholder']  => that box's placeholder
 */

$id = Hash::get($row, $field['data_path']);
if ($id === null) {
    return;
}
$url = str_replace('%id%', rawurlencode((string)$id), $field['url']);
$label = $field['button'] ?? __('Run');
$title = $field['title'] ?? ($label !== '' ? $label : __('Run'));
$icon = empty($field['icon']) ? '' : '<i class="fas fa-' . h($field['icon']) . '"></i>';
$hasInput = !empty($field['text_input']);
?>
<div class="d-flex flex-column gap-1" style="min-width:9rem;"
     data-on-demand data-url="<?= h($url) ?>"
     data-running="<?= h(__('Running…')) ?>">
    <div class="<?= $hasInput ? 'input-group input-group-sm flex-nowrap' : '' ?>">
        <?php if ($hasInput): ?>
            <input type="text" class="form-control" data-on-demand-value
                   placeholder="<?= h($field['placeholder'] ?? '') ?>"
                   aria-label="<?= h($field['placeholder'] ?? $title) ?>">
        <?php endif; ?>
        <button type="button" data-on-demand-run
                class="btn btn-sm btn-outline-secondary text-nowrap"
                title="<?= h($title) ?>" aria-label="<?= h($title) ?>">
            <?= $icon ?><?= $icon !== '' && $label !== '' ? ' ' : '' ?><?= h($label) ?>
        </button>
    </div>
    <div class="small" data-on-demand-result></div>
</div>
