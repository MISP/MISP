<?php
$value = Hash::get($row, $field['data_path']);

echo sprintf('<p class="text-decoration-underline fw-semibold mb-0">
    #%s
    </p>',
    h($value)
);
?>


