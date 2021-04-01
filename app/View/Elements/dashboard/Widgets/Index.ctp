<?php
    echo $this->element('genericElements/IndexTable/index_table', [
        'data' => [
            'data' => $data['data'],
            'top_bar' => [],
            'fields' => $data['fields'],
            'title' => false,
            'description' => false,
            'pull' => 'right',
            'skip_pagination' => true,
            'actions' => []
        ]
    ]);
?>
