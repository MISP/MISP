<?php

$format = Hash::get($row, $field['data_path']);
$inputSource = isset($field['input_source_path'])
    ? Hash::get($row, $field['input_source_path'])
    : null;
$headers = isset($field['headers_path'])
    ? Hash::get($row, $field['headers_path'])
    : null;

if (empty($format) && empty($inputSource) && empty($headers)) {
    return;
}

// Mirrors Feed::$feed_types, kept short enough to sit inside a badge.
$formatLabels = [
    'misp' => 'MISP',
    'freetext' => __('Freetext'),
    'csv' => 'CSV',
];

$sourceLabels = [
    'network' => ['label' => __('Network'), 'icon' => 'globe'],
    'local' => ['label' => __('Local'), 'icon' => 'hard-drive'],
];
$source = $sourceLabels[$inputSource] ?? null;
?>

<div class="d-flex flex-column align-items-start gap-1">

    <?php if (!empty($format)): ?>
        <?= $this->element('genericElementsBS5/Badges/format', [
            'formatName' => $formatLabels[$format] ?? $format,
            'hiddenClass' => ''
        ]) ?>
    <?php endif; ?>

    <?php if (!empty($inputSource)): ?>
        <span class="text-muted small d-inline-flex align-items-center gap-1">
            <i class="fas fa-<?= h($source['icon'] ?? 'question') ?>"></i>
            <?= h($source['label'] ?? $inputSource) ?>
        </span>
    <?php endif; ?>

    <?php if (!empty($headers)): ?>
        <span
            class="badge bg-secondary-subtle text-secondary-emphasis d-inline-flex align-items-center gap-1"
            title="<?= h(__('This feed is pulled with custom HTTP headers. Their values are never displayed.')) ?>"
        >
            <i class="fas fa-lock"></i><?= __('Custom headers') ?>
        </span>
    <?php endif; ?>

</div>
