<?php
$analysis = Hash::extract($row, $field['data_path'])[0];

$analysisLevels = [
    0 => __('Initial'),
    1 => __('Ongoing'),
    2 => __('Completed'),
];

$cssClass = $analysisLevels[$analysis] ?? '';

echo sprintf(
    '<span class="%s">%s</span>',
    $cssClass,
    $analysisLevels[$analysis] ?? __('Unknown')
);

