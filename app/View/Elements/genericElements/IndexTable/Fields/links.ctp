<?php
/**
 *    - url: url to reference. Can have `%s` in it to be replaced by `data_path` extracted value.
 *    - url_params_data_paths: add dynamic URL elements such as an id to the URL. Can be an array with each value added in a separate param. Used if `url` does not have a `%s` marker
 */
    $data_elements = Hash::extract($row, $field['data_path']);
    $url_param_data_paths = '';
    $urlWithData = empty($field['url']) ? '#' : h($field['url']);
    if (!empty($field['url_params_data_paths'])) {
        if (is_array($field['url_params_data_paths'])) {
            $temp = array();
            foreach ($field['url_params_data_paths'] as $path) {
                $extracted_value = Hash::extract($row, $path);
                if (!empty($extracted_value)) {
                    $temp[] = h($extracted_value[0]);
                }
            }
            $url_param_data_paths = implode('/', $temp);
        } else {
            $url_param_data_paths = Hash::extract($row, $field['url_params_data_paths']);
            if (!empty($url_param_data_paths)) {
                $url_param_data_paths = $url_param_data_paths[0];
            } else {
                $url_param_data_paths = '';
            }
        }
        $urlWithData .= '/' . $url_param_data_paths;
    }
    $links = array();
    foreach ($data_elements as $data) {
        if (!empty($data['name'])) {
            $field['title'] = $data['name'];
        }
        if (!empty($data['url'])) {
            $data = $data['url'];
        }
        if (isset($field['url']) && strpos($field['url'], '%s') !== false) {
            $url = sprintf(
                $field['url'],
                $data
            );
        } elseif (!empty($field['url_params_data_paths'])) {
            $url = $urlWithData;
        } else {
            $url = $data;
        }
        $links[] = sprintf(
            '<a href="%s" title="%s">%s</a>',
            h($url),
            empty($field['title']) ? h($data) : h($field['title']),
            empty($field['title']) ? h($data) : h($field['title'])
        );
    }
    echo implode('<br />', $links);
?>
