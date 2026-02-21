<?php
$threatLevel = Hash::extract($row, $field['data_path'])[0];

$threatLevels = [
    1 => __('Low'),
    2 => __('Medium'),
    3 => __('High'),
    4 => __('Undefined'),
];

$cssClass = $threatLevel == 1 ? 'green bold' : ($threatLevel == 2 ? 'orange bold' : ($threatLevel == 3 ? 'red bold' : ''));
echo sprintf(
    '<span class="%s">%s</span>',
    $cssClass,
    $threatLevels[$threatLevel] ?? __('Unknown')
);