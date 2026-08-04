<?php
$type = Hash::extract($row, $field['data_path']);
$type = strtolower($type[0] ?? '');

$config = [
    'attribute' => [
        'icon' => 'tag',
        'label' => __('Attribute'),
        'class' => 'text-primary bg-primary-subtle border-primary-subtle',
        'desc' => __('Standard MISP attribute')
    ],
    'text' => [
        'icon' => 'align-left',
        'label' => __('Text'),
        'class' => 'text-success bg-success-subtle border-success-subtle',
        'desc' => __('Free text field')
    ],
    'file' => [
        'icon' => 'file-import',
        'label' => __('File'),
        'class' => 'text-warning bg-warning-subtle border-warning-subtle',
        'desc' => __('Attachment or file reference')
    ]
];

// Fallback
$current = $config[$type] ?? [
    'icon' => 'question-circle',
    'label' => h($type ?: __('Unknown')),
    'class' => 'text-secondary bg-secondary-subtle border-secondary-subtle',
    'desc' => ''
];
?>

<div class="d-inline-flex align-items-center" data-bs-toggle="tooltip" title="<?= h($current['desc']) ?>">
    <div class="px-2 py-1 rounded border d-flex align-items-center <?= $current['class'] ?>" style="font-size: 0.85rem; font-weight: 600;">
        <i class="fas fa-<?= $current['icon'] ?> me-2"></i>
        <span class="text-uppercase" style="letter-spacing: 0.05em;">
            <?= $current['label'] ?>
        </span>
    </div>
</div>