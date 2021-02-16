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
            $data = '<span class="text-success">' . __('Indefinite') . '</span>';
        } else {
            if ($data <= time()) {
                $title = __('Expired at %s', date('Y-m-d H:i:s', $data));
                $data = '<span class="red bold" title="' . $title . '">' . __('Expired') . '</span>';
            } else {
                $diffInDays = floor(($data - time()) / (3600 * 24));
                $class = $diffInDays <= 14 ? 'text-warning bold' : 'text-success';
                $title = __n('Will expire in %s day', 'Will expire in %s days', $diffInDays, $diffInDays);
                $data = '<span class="' . $class . '" title="' . $title . '">' . $this->Time->time($data) . '</span>';
            }
        }
    }
    if (!empty($field['onClick'])) {
        $data = sprintf(
            '<span onclick="%s">%s</span>',
            $field['onClick'],
            $data
        );
    }
    echo $data;
