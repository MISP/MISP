<?php
    $data_elements = Hash::extract($row, $field['data_path']);
    $links = array();
    foreach ($data_elements as $data) {
        if (strpos($field['url'], '%s') !== false) {
            $url = sprintf(
                $field['url'],
                $data
            );
        } else {
            $url = $data;
        }
        $links[] = sprintf(
            '<a href="%s" title="%s">%s</a>',
            h($url),
            empty($field['title']) ? h($data) : h($field['title']),
            h($data)
        );
    }
    echo implode('<br />', $links);
?>
