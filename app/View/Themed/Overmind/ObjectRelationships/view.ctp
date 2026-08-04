<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => __('Event Report Template Variable view'),
        'data' => $data,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => 'EventReportTemplateVariable.id'
            ],
            [
                'key' => __('Name'),
                'path' => 'EventReportTemplateVariable.name'
            ],
            [
                'key' => __('Value'),
                'path' => 'EventReportTemplateVariable.name'
            ],
        ],
    ]
);
