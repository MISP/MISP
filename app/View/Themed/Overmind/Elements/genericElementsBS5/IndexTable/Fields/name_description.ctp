<?php
$paths = array_map('trim', explode(',', $field['data_path']));

$name        = Hash::extract($row, $paths[0])[0] ?? null;
$description = isset($paths[1]) ? (Hash::extract($row, $paths[1])[0] ?? null) : null;

if (empty($name)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';
?>

<div class="d-flex flex-column gap-1">
    <div class="d-flex align-items-baseline gap-2 mb-0">
        <?php if (!$isCard && !empty($field['distribution_path'])):
            echo $this->element(
                '/genericElementsBS5/IndexTable/Fields/distribution',
                [
                    'row' => $row,
                    'field' => [
                        'data_path' => $field['distribution_path'],
                        'display' => 'short'
                    ]
                ]
            );
        endif; ?>
        <p class="mb-0 fw-semibold">
            <?= h($name); ?>
        </p>
    </div>

    <?php if (!empty($description)): ?>
        <div class="card card-link-item bg-light">
            <div class="card-body p-1">
                <i class="fa fa-comment"></i> 
                <span><?= h($description) ?></span>
            </div>
        </div>
    <?php endif; ?>

</div>