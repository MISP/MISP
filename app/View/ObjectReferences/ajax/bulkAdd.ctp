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
        'title' => __('Relationship type'),
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
        'label' => __('Source Object'),
        'field' => 'source_uuid',
        'class' => 'span6',
        'type' => 'dropdown',
        'picker' => true,
        'options' => $validSourceUuid,
        '_chosenOptions' => [
            'width' => '460px',
        ],
    ],
    sprintf('<p style="margin: 1em 0 0.5em 2em;">%s</p>', __('Target details')),
    sprintf('<pre class="span6" style="max-height: 300px; overflow-y: auto;" id="bulk-target-details">%s</pre>', __('- select an object -')),
    [
        'field' => 'comment',
        'type' => 'textarea',
        'class' => 'input span6',
        'rows' => 3,
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
?>
<script>
    var validSourceUuid = <?= json_encode($eventObjects) ?>;
    $(function() {
        $("#ObjectReferenceRelationshipTypeSelect").change(function() {
            objectReferenceCheckForCustomRelationship()
        });

        updateTargetDetails()
        $('#ObjectReferenceSourceUuid').change(function() {
            updateTargetDetails()
        })
    })

    function submitBulkAddForm() {
        submitGenericFormInPlace(function(data) {
            handleAjaxModalResponse(data, data.id, data.url, 'massEdit', 'event')
        })
    }

    function updateTargetDetails() {
        var objectUuid = $('#ObjectReferenceSourceUuid').find('option:selected').val()
        var selectedObject = validSourceUuid[objectUuid]
        $('#bulk-target-details').text(generateObjectDetails(selectedObject))
    }

    function generateObjectDetails(object) {
        var details = ''
        details += 'Object UUID: ' + object.uuid + '\n'
        details += 'Object name: ' + object.name + '\n\n'
        details += 'Attributes:\n'
        object.Attribute.forEach(function(attribute) {
            details += '  Category: ' + attribute.category + '\n'
            details += '  Type: ' + attribute.type + '\n'
            details += '  Value: ' + attribute.value + '\n\n'
        })
        return details
    }
</script>