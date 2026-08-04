<?php
    $doNotDisplay = false;
    if (!empty($field['onclick'])) {
        if (!empty($field['onclick_params_data_path'])) {
            $data_path_params = [];
            foreach ($field['onclick_params_data_path'] as $data_path) {
                $extracted = Hash::extract($row, $data_path);
                if (empty($extracted)) {
                    $extracted = [null];
                    $doNotDisplay=true;
                }
                $data_path_params[] = $extracted[0];
            }
            $field['onclick'] = vsprintf($field['onclick'], $data_path_params);
        }
    }
    $title = empty($field['title']) ? __('%s toggle', $field['name']) : $field['title'];
    $default = !empty(Hash::extract($row, $field['data_path'])) ? (bool)Hash::extract($row, $field['data_path'])[0] : '';
    echo $doNotDisplay ? '' : sprintf(
        '<div id="%s"><input id="%s%s" type="checkbox" aria-label="%s" onClick="%s" %s /></div>',
        empty($field['checkbox_container']) ? 'GenericCheckboxContainer' : h($field['checkbox_container']),
        empty($field['checkbox_name']) ? 'GenericCheckbox' : h($field['checkbox_name']),
        h($k),
        h($title),
        $field['onclick'],
        $default ? 'checked' : ''
    );
