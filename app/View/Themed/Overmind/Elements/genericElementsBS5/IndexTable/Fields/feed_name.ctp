<?php

$name = Hash::get($row, $field['data_path']);
$distribution = isset($field['distribution_path'])
    ? Hash::get($row, $field['distribution_path'])
    : null;

$hasName = !($name === null || $name === '');
$hasDistribution = !($distribution === null || $distribution === '');
$isCard = isset($viewMode) && $viewMode === 'card';

if (!$hasName && !$hasDistribution) {
    return;
}

$label = h($name);
if ($hasName && !empty($field['url'])) {
    $id = Hash::get($row, $field['id_path'] ?? $field['data_path']);
    $label = sprintf(
        '<a href="%s">%s</a>',
        h(str_replace('%id%', rawurlencode((string)$id), $field['url'])),
        $label
    );
} elseif ($hasName && !empty($viewUrl)) {
    $label = sprintf(
        '<a href="%s" class="link-body-emphasis link-underline-opacity-0 link-underline-opacity-100-hover">%s</a>',
        h($viewUrl),
        $label
    );
}
?>

<span class="d-inline-flex flex-wrap align-items-center gap-2">
    <?php if ($hasDistribution && !$isCard): ?>
        <?= $this->element('genericElementsBS5/Badges/distribution', [
            'distribution' => (int)$distribution,
            'full' => !empty($field['distribution_full'])
        ]) ?>
    <?php endif; ?>

    <?php if ($hasName): ?>
        <span class="fw-semibold"><?= $label ?></span>
    <?php endif; ?>
</span>
