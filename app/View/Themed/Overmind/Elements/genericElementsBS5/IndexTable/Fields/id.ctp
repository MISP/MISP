<?php
$values = Hash::get($row, $field['data_path']);

if (empty($values)) {
    return;
}

$values = is_array($values) ? $values : [$values];
$urlTemplate = $field['url'] ?? '';
?>

<div class="d-flex flex-wrap gap-2">
    <?php foreach ($values as $id):
        $currentUrl = str_replace('%id%', $id, $urlTemplate);
    ?>
        <a class="text-decoration-underline fw-semibold mb-0 text-dark" href="<?= h($currentUrl) ?>">
            <?= sprintf('#%s', h($id)) ?>
        </a>
    <?php endforeach; ?>
</div>