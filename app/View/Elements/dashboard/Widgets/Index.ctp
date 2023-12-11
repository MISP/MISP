<?php
    echo $this->element('genericElements/IndexTable/index_table', [
        'data' => [
            'data' => $data['data'],
            'description' => empty($data['description']) ? false : $data['description'],
            'top_bar' => [],
            'fields' => $data['fields'],
            'title' => false,
            'pull' => 'right',
            'skip_pagination' => true,
            'actions' => []
        ]
    ]);
?>
