<?php
$flag = Hash::extract($row, $field['data_path']);
$flag = empty($flag) ? null : $flag[0];
$icon = $text = $aria = '';
if (!is_null($flag)) {
    $flag = empty($field['boolean_reverse']) ? $flag : !$flag;
}
if (is_null($flag)) {
    $text = __('N/A');
    $aria = __('Not applicable');
} elseif ($flag) {
    $icon = 'check';
    $aria = __('Yes');
} else {
    $icon = 'times';
    $aria = __('No');
}

$classes = ['fa', "fa-$icon"];
if (!empty($field['colors'])) {
    $classes[] = $icon == 'check' ? 'green' : 'grey';
} else {
    $classes[] = 'black';
}

echo sprintf(
    '<i class="%s" role="img" aria-label="%s"></i>%s',
    implode(' ', $classes),
    $aria, $text
);
?>
