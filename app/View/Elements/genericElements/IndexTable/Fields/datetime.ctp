<?php
<<<<<<< HEAD
    $timestamp = Hash::extract($row, $field['data_path'])[0];
    $datetime = (new DateTime())->setTimestamp($timestamp);
    echo h($datetime->format('D, d M Y H:i'));
=======
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
        $data = date('Y-m-d H:i:s', $data);
    }
    if (!empty($field['onClick'])) {
        $data = sprintf(
            '<span onClick="%s">%s</span>',
            $field['onClick'],
            $data
        );
    }
    echo $data;
>>>>>>> 31225680f351556d21ca6f215663fb23db8a6365
?>
