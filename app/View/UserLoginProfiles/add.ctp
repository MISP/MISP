<?php
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => isset($edit) ? __('Edit UserLoginProfile') : __('Add UserLoginProfile'),
        'description' => __('no description.'),
        'fields' => [
            [
                'field' => 'user_id',
                'label' => __('User'),
                'options' => $dropdownData['user'],
                'type' => 'dropdown',
                'class' => 'span6'
            ],
            [
                'field' => 'status',
                'label' => __('Status'),
                'class' => 'span6',
                'rows' => 4,
            ],
            [
                'field' => 'ip',
                'label' => __('IP'),
                'class' => 'span6',
                'rows' => 4,
            ],
            [
                'field' => 'ip',
                'label' => __('IP'),
                'class' => 'span6',
                'rows' => 4,
            ],
            [
                'field' => 'user_agent',
                'label' => __('User-Agent'),
                'class' => 'span6',
                'rows' => 4,
            ]
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);
if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}
