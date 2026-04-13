<?php
$value = Hash::get($row, $field['data_path']);
$url = $field['url'] ?? [];
$url = str_replace('%id%', $value, $url);
?>


<a class="text-decoration-underline fw-semibold mb-0 text-dark" href="<?= h($url) ?>">
    <?= sprintf('#%s', h($value)) ?>
</a>
