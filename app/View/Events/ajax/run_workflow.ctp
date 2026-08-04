

<?php
$fields = [];
if (!empty($workflows)) {
    foreach ($workflows as $wf) {
        $wf = $wf['Workflow'];
        $fields[] = [
            'field' => $wf['id'],
            'label' => sprintf('%s :: %s', h($wf['trigger_id']), h($wf['name'])),
            'type' => 'checkbox',
        ];
    }
    $fields[] = [
        'field' => 'environment_variables',
        'label' => __("Workflow Environment Variables"),
        'type' => 'textarea',
        'class' => 'span5',
        'div' => 'input clear input-append',
        'picker' => [
            'text' => __('Toggle UI'),
            'function' => 'initWorkflowVariablesUI'
        ]
    ];
}

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => __('Select the workflow(s) you wish to run on the selected Event. Note that only Ad-Hoc Workflow with the Trigger Data Input Scope `passed_event_ids` can be used.'),
        'model' => 'Event',
        'title' => __('Run Ad-Hoc Workflows on Event'),
        'fields' => $fields,
        'submit' => [
            'action' => $this->request->params['action'],
        ],
        'metaFields' => [
            $this->element('Workflows/workflowVariablesUI', array(
                'drawToggleButton' => false,
            ))
        ]
    ]
]);
