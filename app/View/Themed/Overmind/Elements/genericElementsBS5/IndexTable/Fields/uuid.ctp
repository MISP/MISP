<?php
$value = Hash::get($row, $field['data_path']);
$url = str_replace('%id%', (string)$value, $field['url'] ?? '');
?>

<?php if ($url === ''): ?>
<span class="fst-italic mb-0"><?= h($value) ?></span>
<?php else: ?>
<a class="text-decoration-none fst-italic mb-0 text-dark" href="<?= h($url) ?>">
    <?= h($value) ?>
</a>
<?php endif; ?>
