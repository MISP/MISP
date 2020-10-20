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
    if (is_bool($data)) {
        $data = sprintf(
            '<i class="black fa fa-%s"></i>',
            $data ? 'check' : 'times'
        );
        $data = '';
    } else {
        $data = h($data);
        if (!empty($field['privacy'])) {
            $data = sprintf(
                '<span class="privacy-value quickSelect" data-hidden-value="%s">****************************************</span>&nbsp;<i class="privacy-toggle fas fa-eye useCursorPointer" title="%s"></i>',
                $data,
                __('Reveal hidden value')
            );
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
