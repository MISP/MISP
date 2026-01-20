<?php

// Dynamically create checkboxes for each type
$typeCheckboxes = [];
foreach ($types as $key => $label) {
    $typeCheckboxes[] = [
        'field' => $key,
        'label' => $label,
        'type' => 'checkbox',
        'default' => !empty($value[$key]) ? 1 : 0,
        'stayInLine' => true
    ];
}

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => isset($edit) ? __('Edit Regexp') : __('Add Regexp'),
        'fields' => array_merge(
            [
                [
                    'field' => 'regexp',
                    'label' => __('Regexp'),
                    'stayInLine' => true
                ],
                [
                    'field' => 'replacement',
                    'label' => __('Replacement')
                ],
                [
                    'label' => __('Types to be affected by the filter'),
                    'type' => 'html',
                    'html' => '<div class="clear">' .
                              __('Types to be affected by the filter (Setting \'all\' will override the other settings)') .
                              '</div><br />'
                ],
                [
                    'field' => 'all',
                    'label' => __('All'),
                    'type' => 'checkbox',
                    'data_path' => 'Regexp.id',
                    'default' => !empty($all) ? 1 : 0
                ]
            ],
            $typeCheckboxes
        ),
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);

echo $this->element('/genericElements/SideMenu/side_menu', [
    'menuList' => 'regexp',
    'menuItem' => isset($edit) ? 'edit' : 'add'
]);

?>
