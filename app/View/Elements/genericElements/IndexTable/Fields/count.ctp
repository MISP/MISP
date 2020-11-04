<?php
    $fieldValue = Hash::extract($row, $field['data_path'])[0];
    if (!empty($field['url'])) {
        if (!empty($field['url_params_data_path'])) {
            $data_path_params = [];
            foreach ($field['url_params_data_path'] as $data_path) {
                $data_path_params[] = Hash::extract($row, $data_path)[0];
            }
            $field['url'] = vsprintf($field['url'], $data_path_params);
        }
        $fieldValue = sprintf(
            '<a href="%s">%s</a>',
            h($field['url']),
            $fieldValue
        );
    }
    echo $fieldValue;
