<?php
    echo '<div class="regexp index">';
    echo $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'title' => __('Import Regexp'),
            'data' => $list,
            'fields' => [
                [
                    'name' => __('ID'),
                    'sort' => 'Regexp.id',
                    'class' => 'short',
                    'data_path' => 'Regexp.id',
                ],
                [
                    'name' => __('Exportable'),
                    'sort' => 'Regexp.regexp',
                    'class' => 'custom-element',
                    'data_path' => 'Regexp.regexp',
                ],
                [
                    'name' => __('Replacement'),
                    'sort' => 'Regexp.replacement',
                    'class' => 'custom-element',
                    'data_path' => 'Regexp.replacement',
                ],
                [
                    'name' => __('Type'),
                    'sort' => 'Regexp.type',
                    'class' => 'short',
                    'data_path' => 'Regexp.type',
                ]
            ]
        ]
    ]);
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'regexp', 'menuItem' => 'index'));
?>
