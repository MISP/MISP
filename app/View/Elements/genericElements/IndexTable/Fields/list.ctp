<?php
    $data = Hash::extract($row, $field['data_path']);
    foreach ($data as &$element) {
        $element = h($element);
    }
    $data = implode('<br />', $data);
    echo $data;
?>
