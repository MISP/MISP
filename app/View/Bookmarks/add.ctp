<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
$fields = [
    [
        'field' => 'name',
        'class' => 'span6',
        'placeholder' => 'Name of the bookmark',
    ],
    [
        'field' => 'url',
        'type' => 'textarea',
        'class' => 'input span6',
    ],
    [
        'field' => 'comment',
        'type' => 'textarea',
        'class' => 'input span6',
    ],
    [
        'field' => 'exposed_to_org',
        'type' => 'checkbox',
        'label' => __('Should this bookmark be exposed to all users from the organisation'),
    ],
];
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => false,
        'model' => 'Bookmark',
        'title' => $edit ? __('Edit Bookmark') : __('Add Bookmark'),
        'fields' => $fields,
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitModalInPlace();'
        ]
    ]
]);

if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}
?>

<script>
    function submitModalInPlace() {
        var $genericForm = $('.genericForm');
        $.ajax({
            type: "POST",
            url: $genericForm.attr('action'),
            data: $genericForm.serialize(), // serializes the form's elements.
            success: function(data) {
                $('#genericModal').modal('hide').remove();
                showMessage('success', '<?= $edit ? __('Bookmark updated') : __('Bookmark created') ?>');
            },
            error: xhrFailCallback,
        });
    }
</script>
