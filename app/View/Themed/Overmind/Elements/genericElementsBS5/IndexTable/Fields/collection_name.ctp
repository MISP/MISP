<?php
$collection = Hash::extract($row, $field['data_path']);

if (empty($collection)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';
?>

<div class="d-flex flex-column gap-1">
    <div class="d-flex align-items-baseline gap-2 mb-0">
        <?php if (!$isCard) {
                echo $this->element(
                    '/genericElementsBS5/IndexTable/Fields/distribution',
                    [
                        'row' => $row,
                        'field' => [
                            'data_path' => 'Collection.distribution',
                            'display' =>'short'
                        ]
                    ]
                );
            }
        ?>
        <p class="mb-0">
            <?= h($collection['name']); ?>
    </p>

    </div>

    <!-- Show if it contains a description -->
    <?php if (!empty($collection['description'])): ?>
        <div class="card card-link-item" style="background-color: #f8f9fa;">
            <div class="card-body p-1">
                <i class="fa fa-comment"></i> 
                <span><?= h($collection['description']) ?></span>
            </div>
        </div>
    <?php endif; ?>

</div>