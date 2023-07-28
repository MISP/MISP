<?php
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => __("If you already are enrolled on this instance, but forgot your password, you can request a new password below.") . '<br />' . __("An e-mail containing URL with an embedded token will be sent to you that you can use to reset the password within 10 minutes."),
        'model' => 'User',
        'title' => __('Forgotten password'),
        'fields' => [
            [
                'field' => 'email',
                'class' => 'span6'
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);