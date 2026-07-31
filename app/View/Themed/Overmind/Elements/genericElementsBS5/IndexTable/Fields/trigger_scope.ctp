<?php

$scope = Hash::get($row, $field['data_path']) ?? '';
if ($scope === '') {
    // Optional: ad-hoc workflows have no data-input scope until their trigger
    // node is configured in the editor, and saying so beats an empty cell.
    if (!empty($field['empty_text'])) {
        printf('<span class="text-muted small fst-italic">%s</span>', h($field['empty_text']));
    }
    return;
}
?>
<span class="badge rounded-pill fw-normal"
      style="font-size:.72rem;background:var(--bs-tertiary-bg);color:var(--bs-secondary-color);border:1px solid var(--bs-border-color);">
    <?= h($scope) ?>
</span>
