

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
}

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => __('Select the workflow(s) you wish to run on the selected Event. Note that only Ad-Hoc Workflow with the Trigger Data Input Scope `passed_event_ids` can be used.'),
        'model' => 'Event',
        'title' => __('Run Ad-Hoc Workflows on Event'),
        'fields' => $fields,
        'submit' => [
            'action' => $this->request->params['action'],
        ]
    ]
]);
