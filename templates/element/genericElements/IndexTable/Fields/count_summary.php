<?php
/*
'name' => __('Members'),
'data_path' => 'alignments',
'element' =>  'count_summary',
'url' => '/individuals/index/?organisation_id={{url_data}}',
'url_data_path' => 'id'
*/
    $data = $this->Hash->extract($row, $field['data_path']);
    if (!empty($field['url_data_path'])) {
        $url_data_path = $this->Hash->extract($row, $field['url_data_path'])[0];
    }
    if (!empty($field['url']) && count($data) > 0) {
        if (!empty($url_data_path)) {
            $field['url'] = str_replace('{{url_data}}', $url_data_path, $field['url']);
        }
        echo sprintf(
            '<a href="%s%s">%s</a>',
            $baseurl,
            h($field['url']),
            count($data)
        );
    } else {
        echo count($data);
    }
?>
