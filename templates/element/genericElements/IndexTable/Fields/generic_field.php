<?php
    $data = $this->Hash->extract($row, $field['data_path']);
    if (is_array($data)) {
        if (count($data) > 1) {
            $data = implode('</br> ', array_map('h', $data));
        } else {
            if (count($data) > 0) {
                $data = h($data[0]);
            } else {
                $data = '';
            }
        }
    } else {
        $data = h($data);
    }
    if (is_bool($data)) {
        $data = sprintf(
            '<i class="fa fa-%s"></i>',
            $data ? 'check' : 'times'
        );
    } else {
        if (!empty($field['options'])) {
            $options = $this->Hash->extract($row, $field['options']);
            if (!empty($options)) {
                $data = h($options[$data]);
            }
        }
        if (!empty($field['privacy'])) {
            $data = sprintf(
                '<span class="privacy-value" data-hidden-value="%s">****************************************</span> <i class="privacy-toggle fas fa-eye useCursorPointer"></i>',
                $data
            );
        }
    }
    if (!empty($field['url'])) {
        if (!empty($field['url_vars'])) {
            if (!is_array($field['url_vars'])) {
                $field['url_vars'] = [$field['url_vars']];
            }
            foreach ($field['url_vars'] as $k => $path) {
                $field['url'] = str_replace('{{' . $k . '}}', $this->Hash->extract($row, $path)[0], $field['url']);
            }
        }
        $data = sprintf(
            '<a href="%s%s">%s</a>',
            $baseurl,
            h($field['url']),
            $data
        );
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
