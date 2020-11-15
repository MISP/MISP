<?php

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => __('Add auth key'),
        'description' => __('Auth keys are used for API access. A user can have more than one authkey, so if you would like to use separate keys per tool that queries MISP, add additional keys. Use the comment field to make identifying your keys easier.'),
        'fields' => [
            [
                'field' => 'user_id',
                'label' => __('User'),
                'options' => $dropdownData['user'],
                'type' => 'dropdown'
            ],
            [
                'field' => 'comment',
                'class' => 'span6'
            ],
            [
                'field' => 'expiration',
                'label' => 'Expiration',
                'class' => 'datepicker span6',
                'placeholder' => "YYYY-MM-DD",
                'type' => 'text'
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
