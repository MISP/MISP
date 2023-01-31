<?php
$value = Cake\Utility\Hash::extract($data, $field['path']);
if (!empty($field['pill'])) {
    echo sprintf(
        '<span class="%s">%s</span>',
        !empty($value[0]) ? 'badge bg-success' : 'badge bg-danger',
        !empty($value[0]) ? __('Yes') : __('No')
    );
} else {
    echo sprintf(
        '<i class="fas fa-%s"></i>',
        empty($value[0]) ? 'times' : 'check'
    );
}