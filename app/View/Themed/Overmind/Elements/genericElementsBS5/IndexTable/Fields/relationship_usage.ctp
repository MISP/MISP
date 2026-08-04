<?php

$usage = Hash::extract($row, $field['data_path']);


$objRef = $usage['object_reference'] ?? 0;
$tagRel = $usage['tag_relationship'] ?? 0;
$anaRel = $usage['analyst_relationship'] ?? 0;


$metrics = [
    [
        'icon' => 'project-diagram',
        'value' => $objRef,
        'title' => __('# of Object Reference using this relationship'),
        'color' => 'primary'
    ],
    [
        'icon' => 'tag',
        'value' => $tagRel,
        'title' => __('# of Tag Relationship using this relationship'),
        'color' => 'warning'
    ],
    [
        'icon' => 'arrow-up',
        'value' => $anaRel,
        'title' => __('# of Analyst Relationship using this relationship'),
        'color' => 'success'
    ]
];
?>

<div class="d-flex align-items-center gap-2">
    <?php foreach ($metrics as $metric): ?>
        <div class="d-flex align-items-center bg-light border rounded px-2 py-1" 
             style="min-width: 45px;" 
             data-bs-toggle="tooltip" 
             title="<?= h($metric['title']) ?>">

            <i class="fas fa-<?= $metric['icon'] ?> text-<?= $metric['color'] ?> me-2" style="font-size: 0.85rem;"></i>

            <span class="fw-bold small <?= $metric['value'] > 0 ? 'text-dark' : 'text-muted opacity-50' ?>">
                <?= h($metric['value']) ?>
            </span>
        </div>
    <?php endforeach; ?>
</div>