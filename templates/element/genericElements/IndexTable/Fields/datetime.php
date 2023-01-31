<?php
    $data = $this->Hash->extract($row, $field['data_path']);
    if (is_array($data)) {
        if (count($data) > 1) {
            $data = implode(', ', $data);
        } else {
            if (count($data) > 0) {
                $data = $data[0];
            } else {
                $data = '';
            }
        }
    }
    $data = h($data);
    if (is_numeric($data)) {
        if ($data == 0) {
            __('N/A');
        } else {
            $data = date('Y-m-d H:i:s', $data);
        }
    }
    if (!empty($field['onClick'])) {
        $data = sprintf(
            '<span onClick="%s">%s</span>',
            $field['onClick'],
            $data
        );
    }
    echo $data;
?>
