<?php
    $data = Hash::extract($row, $field['data_path']);
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
            $data = '<span class="text-primary font-weight-bold">' . __('Indefinite') . '</span>';
        } else {
            if ($data <= time()) {
                $data = '<span class="text-danger font-weight-bold">' . __('Expired') . '</span>';
            } else {
                $data = '<span class="text-success font-weight-bold">' . date('Y-m-d H:i:s', $data) . '</span>';
            }
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
