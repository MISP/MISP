<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('Event Report Template Variables');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('View the variables which can be used in an Event Report. These variables can be used to insert dynamic content into your reports, such as lists of attributes, event details, or any other information relevant to the report.');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('EventReportTemplateVariables', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add Variable'),
        'icon' => 'plus',
        'url' => $baseurl . '/EventReportTemplateVariables/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'EventReportTemplateVariable.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'EventReportTemplateVariable.id',
        'data_path' => 'EventReportTemplateVariable.id',
        'element' => 'id',
        //'url' => $baseurl . '/eventReportTemplateVariables/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'EventReportTemplateVariable.name',
        'data_path' => 'EventReportTemplateVariable.name',
        'element' => 'event_report_template_name',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [

        'name' => __('Value'),
        'sort' => 'EventReportTemplateVariable.value',
        'data_path' => 'EventReportTemplateVariable.value',
        'element' => 'custom',
        'function' => function (array $templateVariable) {
            $text = $templateVariable['EventReportTemplateVariable']['value'];
            $maxLength = 1000;
            $maxLines = 20;
            $truncated = false;
            if (mb_strlen($text) > $maxLength) {
                $text = mb_substr($text, 0, $maxLength);
                $truncated = true;
            }
            if (substr_count($text, "\n") > $maxLines) {
                $lines = explode("\n", $text);
                $text = implode("\n", array_slice($lines, 0, $maxLines));
                $truncated = true;
            }
            $text = !$truncated ? $text : $text . ' …';
            return sprintf('<pre class="mb-0">%s</pre>', h($text));
        },
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'EventReportTemplateVariable.id',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/EventReportTemplateVariables/edit/%id%',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/EventReportTemplateVariables/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $isSiteAdmin
            ]
        ]
    ],
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => 'Search',
                        'placeholder' => 'Search in all fields',
                        'name'        => '',
                        'mode'        => 'quickFilter',
                    ],
                ],
                'delete' => '/deleteSelection',
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/EventReportTemplateVariables'
]);
