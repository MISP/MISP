<?php
$fields = [
    [
        'field' => 'email',
        'class' => 'span3 log-search-field',
        'stayInLine' => 1,
        'data-field' => 'email'
    ],
    [
        'field' => 'org',
        'class' => 'span3 log-search-field',
        'requirement' => empty($orgRestriction),
        'label' => __('Organisation'),
        'data-field' => 'org'
    ],
    [
        'field' => 'ip',
        'class' => 'span3 log-search-field',
        'requirement' => !empty(Configure::read('MISP.log_client_ip')),
        'label' => 'IP',
        'data-field' => 'ip'
    ],
    [
        'field' => 'model',
        'class' => 'span3 log-search-field',
        'options' => $dropdownData['model'],
        'type' => 'dropdown',
        'stayInLine' => 1,
        'data-field' => 'model'
    ],
    [
        'field' => 'model_id',
        'class' => 'span3 log-search-field',
        'label' => __('Model ID'),
        'data-field' => 'model_id'
    ],
    [
        'field' => 'action',
        'class' => 'span3 log-search-field',
        'label' => __('Action'),
        'options' => $dropdownData['actions'],
        'required' => false,
        'type' => 'dropdown',
        'data-field' => 'action'
    ],
    [
        'field' => 'title',
        'class' => 'span3 log-search-field',
        'label' => __('Title'),
        'stayInLine' => 1,
        'data-field' => 'title'
    ],
    [
        'field' => 'change',
        'class' => 'span3 log-search-field',
        'label' => __('Change'),
        'data-field' => 'change'
    ],
    [
        'field' => 'from',
        'label' => __('From (YYYY-MM-DD)'),
        'class' => 'datepicker form-control span3 log-search-field',
        'stayInLine' => 1,
        'data-field' => 'from'
    ],
    [
        'field' => 'from_time',
        'class' => 'span3 log-search-field',
        'label' => __('From time (requires from)'),
        'placeholder' => __("HH:MM:SS"),
        'data-field' => 'from_time'
    ],
    [
        'field' => 'to',
        'label' => __('To (YYYY-MM-DD)'),
        'class' => 'datepicker form-control span3 log-search-field',
        'stayInLine' => 1,
        'data-field' => 'to'
    ],
    [
        'field' => 'to_time',
        'class' => 'span3 log-search-field',
        'label' => __('To time (requires to)'),
        'placeholder' => __("HH:MM:SS"),
        'data-field' => 'to_time'
    ]
];
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => false,
        'model' => 'Log',
        'title' => __('Search Logs'),
        'fields' => $fields,
        'submit' => [
            'action' => 'index',
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ],
    'formOptions' => [
        'url' => $baseurl . '/logs/index'
    ],
]);

if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}

