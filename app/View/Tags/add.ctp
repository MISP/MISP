<?php
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => isset($edit) ? __('Edit Tag') : __('Add Tag'),
        'fields' => [
            [
                'field' => 'name',
                'label' => __('Name')
            ],
            [
                'field' => 'colour',
                'label' => __('Colour'),
                'class' => 'colorpicker-element'
            ],
            [
                'field' => 'org_id',
                'label' => __('Restrict tagging to org'),
                'options' => $orgs,
                'type' => 'dropdown'
            ],
            [
                'field' => 'user_id',
                'label' => __('Restrict tagging to user'),
                'options' => $isSiteAdmin ? $users : null,
                'type' => 'dropdown',
                'requirements' => $isSiteAdmin,
            ],
            [
                'field' => 'exportable',
                'default' => 1,
                'type' => 'checkbox'
            ],
            [
                'field' => 'hide_tag',
                'type' => 'checkbox'
            ],
            [
                'field' => 'local_only',
                'label' => __('Enforce this tag to be used as local only'),
                'type' => 'checkbox'
            ]
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);
if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}
?>
<script>
    $(function() {
        $('#TagColour').colorpicker();
    });
</script>
