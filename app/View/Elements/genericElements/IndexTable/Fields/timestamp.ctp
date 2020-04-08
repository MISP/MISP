<?php
    $timestamp = Hash::extract($row, $field['data_path'])[0];
    if (!empty($field['time_format'])) {
        $timestamp = date($field['time_format'], $timestamp);
    }
    echo h($timestamp);
?>
