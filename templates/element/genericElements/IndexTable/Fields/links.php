<?php
/**
 *    - url: A url to link to. Can include placeholders for variables using the {{0}} notation
 *    - url_vars: ordered list of parameters, to be used as replacements in the url (first parameter would replace {{0}} for example)
 */
    $data_elements = $this->Hash->extract($row, $field['data_path']);
    $url_param_data_paths = '';
    $urlWithData = empty($field['url']) ? '#' : h($field['url']);
    if (!empty($field['url_params_data_paths'])) {
        if (is_array($field['url_params_data_paths'])) {
            $temp = array();
            foreach ($field['url_params_data_paths'] as $k => $path) {
                $extracted_value = $this->Hash->extract($row, $path);
                if (!empty($extracted_value)) {
                    if (is_string($k)) { // associative array, use cake's parameter
                        $temp[] = h($k) . ':' . h($extracted_value[0]);
                    } else {
                        $temp[] = h($extracted_value[0]);
                    }
                }
            }
            $url_param_data_paths = implode('/', $temp);
        } else {
            $url_param_data_paths = $this->Hash->extract($row, $field['url_params_data_paths']);
            if (empty($url_param_data_paths)) {
                $url_param_data_paths = '';
            }
        }
    }
    $links = array();
    foreach ($data_elements as $k => $data) {
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
            if (!empty($url_param_data_paths)) {
                if (is_array($url_param_data_paths)) {
                    $urlWithData .= '/' . $url_param_data_paths[$k];
                } else {
                    $urlWithData .= '/' . $url_param_data_paths;
                }
            }
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
