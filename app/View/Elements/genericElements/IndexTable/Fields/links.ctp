<?php
    $url_data = Hash::extract($row, $field['data_path']);
    $links = array();
    foreach ($url_data as $url) {
        $links[] = sprintf(
            '<a href="%s" title="%s">%s</a>',
            h($url['url']),
            h($url['name']),
            h($url['name'])
        );
    }
    echo implode('<br />', $links);
?>
