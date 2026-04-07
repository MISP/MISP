<?php
/*
 * category.ctp
 *
 * Expected:
 * $data_path => item.category'
 */

$category = Hash::extract($row, $field['data_path']);

if (empty($category)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

echo $this->element(
    'genericElementsBS5/Badges/category',
    [
        'category' => $category[0],
        'full' => $isCard
    ]
);
?>