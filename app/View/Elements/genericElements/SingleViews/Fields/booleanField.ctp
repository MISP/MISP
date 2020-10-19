<?php
$value = Hash::extract($data, $field['path']);
echo sprintf(
    '<i class="fas fa-%s"></i>',
    empty($value[0]) ? 'times' : 'check'
);
