<?php
$modelForForm = 'Event';
echo $this->element('genericElements/Form/genericForm', [
    'form' => $this->Form,
    'data' => [
        'title' => __('Export the %s selected events into the selected format', count($idArray)),
        'model' => $modelForForm,
        'fields' => [
            [
                'field' => 'id',
                'type' => 'hidden',
            ],
            [
                'field' => 'returnFormat',
                'label' => __('RestSearch Export Format'),
                'class' => 'input span6',
                'div' => 'input clear',
                'type' => 'select',
                'options' => Hash::combine($exportFormats, '{n}', '{n}'),
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
        ],
    ],
]);
