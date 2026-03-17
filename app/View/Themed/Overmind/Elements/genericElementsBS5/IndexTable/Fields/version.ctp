<?php
$version = Hash::get($row, $field['data_path']);

echo sprintf(
    '<span class="badge bg-primary-subtle text-primary fw-semibold px-3 py-2">
        v%s
    </span>',
    h($version)
);
?>