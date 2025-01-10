<?php
echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'skip_pagination' => true,
        'data' => !empty($data) ? $data : [],
        'top_bar' => [],
        'fields' => !empty($fields) ? $fields : [],
        'title' => !empty($title) ? h($title) : __('Index'),
        'description' => !empty($description) ? h($description) : '',
        'actions' => !empty($actions) ? $actions : []
    ],
]);