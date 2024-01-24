<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
$fields = [
    [
        'field' => 'object_type',
        'class' => 'span2',
        'disabled' => !empty($this->data[$modelSelection]['object_type']),
        'default' => empty($this->data[$modelSelection]['object_type']) ? null : $this->data[$modelSelection]['object_type'],
        'options' => $dropdownData['valid_targets'],
        'type' => 'dropdown',
        'stayInLine' => 1
    ],
    [
        'field' => 'object_uuid',
        'class' => 'span4',
        'disabled' => !empty($this->data[$modelSelection]['object_uuid']),
        'default' => empty($this->data[$modelSelection]['object_uuid']) ? null : $this->data[$modelSelection]['object_uuid']
    ],
    [
        'field' => 'distribution',
        'class' => 'input',
        'options' => $dropdownData['distributionLevels'],
        'default' => isset($attribute['Attribute']['distribution']) ? $attribute['Attribute']['distribution'] : $initialDistribution,
        'stayInLine' => 1,
        'type' => 'dropdown'
    ],
    [
        'field' => 'sharing_group_id',
        'class' => 'input',
        'options' => $dropdownData['sgs'],
        'label' => __("Sharing Group"),
        'type' => 'dropdown'
    ]
];

if ($modelSelection === 'Note') {
    $fields = array_merge($fields,
        [
            [
                'field' => 'language',
                'class' => 'span3'
            ],
            [
                'field' => 'note',
                'type' => 'textarea',
                'class' => 'input span6'
            ]
        ]
    );
} else if ($modelSelection === 'Opinion') {
    $fields = array_merge($fields,
        [
            [
                'field' => 'opinion',
                'class' => '',
                'type' => 'opinion'
            ],
            [
                'field' => 'comment',
                'type' => 'textarea',
                'class' => 'input span6'
            ]
        ]
    );

} else if ($modelSelection === 'Relationship') {

}
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => false,
        'model' => $modelSelection,
        'title' => $edit ? __('Edit %s', $modelSelection) : __('Add new %s', $modelSelection),
        'fields' => $fields,
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace(analystDataSubmitSuccess, true);'
        ]
    ]
]);

if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}
?>

<script>
    function analystDataSubmitSuccess(data) {
        <?php if ($edit): ?>
            replaceNoteInUI(data)
        <?php else: ?>
            addNoteInUI(data)
        <?php endif; ?>
    }

    function replaceNoteInUI(data) {
        var noteType = Object.keys(data)[0]
        var noteHTMLID = '#' + data[noteType].note_type_name + '-' + data[noteType].id
        var $noteToReplace = $(noteHTMLID)
        if ($noteToReplace.length == 1) {
            console.log(data);
            var compiledUpdatedNote = renderNote(data[noteType])
            $noteToReplace[0].outerHTML = compiledUpdatedNote
            $(noteHTMLID).css({'opacity': 0})
            setTimeout(() => {
                $(noteHTMLID).css({'opacity': 1})
            }, 750);
        }
    }

    function addNoteInUI(data) {
        location.reload()
    }
</script>