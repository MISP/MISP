<?php
    $data = $this->Hash->extract($row, $field['data_path']);
    foreach ($data as $key => $element) {
        if (!is_numeric($key)) {
            $data[$key] = sprintf(
                '<span>%s</span>: %s',
                h($key),
                h($element)
            );
        } else {
            $data[$key] = h($element);
        }
    }
    $data = implode('<br />', $data);
    echo $data;
?>
