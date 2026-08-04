<?php
    $timestamp = Hash::extract($row, $field['data_path'])[0];
    $raw = false;
    if (!empty($field['time_format'])) {
        $timestamp = date($field['time_format'], $timestamp);
    } else if (!empty($field['ago'])) {
        if (date('Ymd') == date('Ymd', $timestamp)) {
            $offset = time() - $timestamp;
            $unit = 'second(s)';
            $colour = 'red';
            if ($offset >= 60) {
                $offset = ceil($offset / 60);
                $unit = 'minute(s)';
                $colour = 'orange';
                if ($offset >= 60) {
                    $offset = ceil($offset / 60);
                    $unit = 'hour(s)';
                    $colour = 'green';
                    if ($offset >= 24) {
                        $offset = floor($offset / 24);
                        $unit = 'day(s)';
                    }
                }
            }
            $raw = true;
            $timestamp = sprintf('<span class="bold %s">%s %s ago</span>', $colour, $offset, $unit);
        } else {
            $timestamp = date('Y-m-d H:i:s', $timestamp);
        }
    }
    echo $raw ? $timestamp : h($timestamp);
?>
