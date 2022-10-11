<?php
$selectedAttributeHTML = '<ul>';

foreach ($selectedAttributes as $attribute) {
    $selectedAttributeHTML .= sprintf('<li>[%s] %s :: %s</li>', h($attribute['id']), h($attribute['type']), h($attribute['value']));
}
$selectedAttributeHTML .= '</ul>';

$fields = [
    sprintf('<h4>%s</h4>', __n('Target Attribute', 'Target Attributes', count($selectedAttributes))),
    $selectedAttributeHTML,
    sprintf('<h4>%s</h4>', __('Object Reference')),
    [
        'field' => 'relationship_type_select',
        'type' => 'dropdown',
        'class' => 'span6',
        'options' => $relationships,
        'picker' => true,
        '_chosenOptions' => [
            'width' => '460px',
        ],
    ],
    [
        'field' => 'relationship_type',
        'class' => 'span6',
        'div' => 'hidden',
    ],
    [
        'field' => 'source_uuid',
        'class' => 'span6',
        'type' => 'dropdown',
        'picker' => true,
        'options' => $validSourceUuid,
        '_chosenOptions' => [
            'width' => '460px',
        ],
    ],
    [
        'field' => 'comment',
        'type' => 'textarea',
        'class' => 'input span6'
    ],

];
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => false,
        'model' => 'ObjectReference',
        'title' => __('Bulk add object references to selected attributes'),
        'fields' => $fields,
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitBulkAddForm();'
        ]
    ]
]);

if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}

?>

<script>
    $(document).ready(function() {
        $("#ObjectReferenceRelationshipTypeSelect").change(function() {
            objectReferenceCheckForCustomRelationship()
        });
    })

    function submitBulkAddForm() {
        submitGenericFormInPlace(function(data) {
            handleAjaxModalResponse(data, data.id, data.url, 'massEdit', 'event')
        })
    }
</script>