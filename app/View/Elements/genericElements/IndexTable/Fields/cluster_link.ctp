<?php
    $cluster = Hash::extract($row, $field['data_path']);
    $url_param_data_paths = '';
    $urlWithData = empty($field['url']) ? '#' : h($field['url']);
    if (!empty($field['url_params_data_paths'])) {
        if (is_array($field['url_params_data_paths'])) {
            $temp = array();
            foreach ($field['url_params_data_paths'] as $path) {
                $temp[] = h(Hash::extract($row, $path)[0]);
            }
            $url_param_data_paths = implode('/', $temp);
        } else {
            $url_param_data_paths = h(Hash::extract($row, $field['url_params_data_paths'])[0]);
        }
        $urlWithData .= '/' . $url_param_data_paths;
    }
    $link = sprintf(
        '<a href="%s" title="%s">%s</a>',
        h($urlWithData),
        sprintf('%s&#10;Version: %s', h($cluster['description']), h($cluster['version'])),
        sprintf('%s :: %s', h($cluster['type']), h($cluster['value']))
    );
    echo $link;
?>
