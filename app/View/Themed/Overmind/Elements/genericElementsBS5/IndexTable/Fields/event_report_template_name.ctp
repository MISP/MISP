<?php
$name = Hash::get($row, $field['data_path']);
if (empty($name)) {
    return;
}
?>

<div class="d-inline-flex align-items-center bg-light rounded border border-secondary-subtle p-1">
    <span class="px-2 py-0.5 bg-dark text-white rounded-start small fw-bold">
        {{
    </span>
    <code class="px-2 py-0.5 bg-transparent text-dark fw-semibold small">
        <?= h($name) ?>
    </code>
    <span class="px-2 py-0.5 bg-dark text-white rounded-end small fw-bold">
        }}
    </span>
</div>