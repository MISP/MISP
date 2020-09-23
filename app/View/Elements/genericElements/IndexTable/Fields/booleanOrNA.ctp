<?php
$flag = Hash::extract($row, $field['data_path']);
$flag = empty($flag) ? null : $flag[0];
$icon = $text = $aria = '';
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

echo sprintf(
    '<i class="black fa fa-%s" role="img" aria-label="%s"></i>%s',
    $icon, $aria, $text
);
?>
