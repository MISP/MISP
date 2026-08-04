<?php
$name = Hash::get($row, $field['data_path']);

if (empty($name)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';
?>

<div class="d-flex align-items-baseline gap-2 mb-0">
    <?php if (!$isCard):
        echo $this->element(
            '/genericElementsBS5/IndexTable/Fields/distribution',
            [
                'row' => $row,
                'field' => [
                    'data_path' => 'EventReport.distribution',
                    'display' => 'short'
                ]
            ]
        );
    endif; ?>
    <p class="mb-0 fw-semibold">
        <?= h($name) ?>
    </p>
</div>
