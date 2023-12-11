<?php
    $data = Hash::extract($row, $field['data_path']);
    if (!empty($field['empty']) && empty($data)) {
        $data = $field['empty'];
    }
    if (is_array($data)) {
        if (count($data) > 1) {
            $implodeGlue = isset($field['array_implode_glue']) ? $field['array_implode_glue'] : ', ';
            $data = implode($implodeGlue, array_map('h', $data));
        } else {
            if (count($data) > 0) {
                $data = h($data[0]);
            } else {
                $data = '';
            }
        }
    } else if (is_bool($data)) {
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
