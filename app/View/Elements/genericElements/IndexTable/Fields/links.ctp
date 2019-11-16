<?php
    $data_elements = Hash::extract($row, $field['data_path']);
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
