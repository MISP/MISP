<?php
$formattedElements = [];

foreach ($elements as $element) {
    $flat = $element['TemplateElement'];

    foreach (['TemplateElementAttribute', 'TemplateElementFile', 'TemplateElementText'] as $child) {
        if (!empty($element[$child])) {

            $childData = $element[$child];
            if (isset($childData[0])) {
                $childData = $childData[0];
            }
            unset($childData['id']);
            if(!empty($childData['text'])){
                $childData['description'] = $childData['text'];
            }
            $flat = array_merge($flat, $childData);

            break;
        }
    }

    $formattedElements[] = $flat;
}

$elements = $formattedElements;

$fields = [
    [
        'element' => 'selector',
        'data_path' => 'id',
        'card_section' => 'selector',
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/templateElements/editV2/%id%',
                'requirement' => $me['Role']['perm_template']
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/templateElements/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $me['Role']['perm_template']
            ],
        ]
    ],

    [
        'name' => __('ID'),
        //'sort' => 'id',
        'data_path' => 'id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Definition'),
        //'sort' => 'definition',
        'data_path' => 'element_definition',
        'element' => 'element_definition',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        //'sort' => 'TemplateElement.name',
        'data_path' => 'name, description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Category'),
        //'sort' => 'category',
        'data_path' => 'category',
        'element' => 'category',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Type'),
        //'sort' => 'type',
        'data_path' => 'type',
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Malware'),
        //'sort' => 'malware',
        'data_path' => 'malware',
        'element' => 'malware',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Mandatory'),
        //'sort' => 'mandatory',
        'data_path' => 'mandatory',
        'element' => 'mandatory',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Batch'),
        //'sort' => 'batch',
        'data_path' => 'batch',
        'element' => 'batch',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('To IDS'),
        //'sort' => 'to_ids',
        'data_path' => 'to_ids',
        'element' => 'ids',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
];

/**
 * Scaffold
 */
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $formattedElements,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    // Has to be implemented in the controller first
                    // [
                    //     'type' => 'search',
                    //     'button' => __('Search'),
                    //     'placeholder' => __('Search by element name'),
                    //     'name'          => 'quickFilter',
                    //     'mode'      => 'quickFilter',
                    // ]
                ],
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/templateElements'
]);

?>