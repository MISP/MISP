<?php
if (empty($field['button']) || empty($field['button']['js_action'])) {
    return;
}

$button = $field['button'];
$jsParam = !empty($button['js_param_path']) ?
    Hash::get($row, $button['js_param_path']) : null;
$containerId = null;

if (
    !empty($button['cell_id']) &&
    !empty($button['cell_id_param_path'])
) {
    $idValue = Hash::get($row, $button['cell_id_param_path']);
    if ($idValue !== null) {
        $containerId = sprintf($button['cell_id'], $idValue);
    }
}

$onClick = $jsParam !== null ?
    sprintf("%s('%s');", $button['js_action'], h($jsParam)) :
    sprintf("%s();", $button['js_action']);

$label = $button['label'] ?? __('Run');
$title = $button['title'] ?? $label;
$resultId = !empty($button['result_id']) ?
    sprintf($button['result_id'], Hash::get($row, 'Server.id')) : null;
?>
<div<?= $containerId ? ' id="' . h($containerId) . '"' : '' ?>>
    <button
        type="button"
        class="btn btn-sm btn-outline-primary text-nowrap"
        title="<?= h($title) ?>"
        aria-label="<?= h($title) ?>"
        onclick="<?= h($onClick) ?>"
    >
        <?= h($label) ?>
    </button>
    <div
        class="server-action-result mt-2 small"
        <?= !empty($resultId) ? 'id="' . h($resultId) . '"' : '' ?>
    ></div>
</div>
