<?php
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => $this->action === 'add' ? __('Add Correlation Exclusion Entry') : __('Edit Correlation Exclusion Entry'),
        'description' => __('If you wish to exclude certain entries from being correlated on, simply add an entry here.'),
        'fields' => [
            [
                'field' => 'value',
                'label' => __('Value'),
                'class' => 'span6',
                'requirements' => $this->action === 'add',
                'type' => 'textarea'
            ],
            [
                'field' => 'comment',
                'label' => __('Comment'),
                'class' => 'span6',
                'type' => 'textarea'
            ]
        ],
        'submit' => [
            'action' => $this->request->params['action']
        ]
    ]
]);
if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}
