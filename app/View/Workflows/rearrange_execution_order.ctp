<?php
$modelForForm = 'Workflow';
echo $this->element('genericElements/Form/genericForm', [
    'form' => $this->Form,
    'data' => [
        'title' => __('Rearrange Execution Order'),
        'model' => $modelForForm,
        'fields' => [
            [
                'field' => 'workflow_order',
                'class' => 'span6',
                'type' => 'textarea'
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => sprintf('submitPopoverForm(\'%s\', \'rearrangeExecutionOrder\', 0, 1)', h($trigger['id']))
        ],
    ]
]);

if (empty($ajax)) {
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'workflows', 'menuItem' => $this->request->params['action']));
}
