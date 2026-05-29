<?php
$data = Hash::extract($row, $field['data_path']);
if (!empty($data) && is_array($data)) {
    foreach ($data as $elements) {
        if (is_array($elements)) {
            foreach ($elements as $key => $values) {
                if (!empty($values) && is_array($values)) {
                    foreach ($values as $value) {
                        echo h($value) . '<br>';
                    }
                }
            }
        }
    }
}
?>
