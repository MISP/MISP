<?php
    if (!empty($field['onclick'])) {
        if (!empty($field['onclick_params_data_path'])) {
            $data_path_params = [];
            foreach ($field['onclick_params_data_path'] as $data_path) {
                $data_path_params[] = Hash::extract($row, $data_path)[0];
            }
            $field['onclick'] = vsprintf($field['onclick'], $data_path_params);
        }
    }
    $title = empty($field['title']) ? __('%s toggle', $field['name']) : $field['title'];
    $default = (bool)Hash::extract($row, $field['data_path'])[0];
    echo sprintf(
        '<div id="%s"><input id="%s%s" type="checkbox" aria-label="%s" onClick="%s" %s /></div>',
        empty($field['checkbox_container']) ? 'GenericCheckboxContainer' : h($field['checkbox_container']),
        empty($field['checkbox_name']) ? 'GenericCheckbox' : h($field['checkbox_name']),
        h($k),
        h($title),
        $field['onclick'],
        $default ? 'checked' : ''
    );
