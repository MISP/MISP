<!-- <div id="genericModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="genericModalLabel" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">
            <span aria-hidden="true">&times;</span>
        </button>
        <h3 id="genericModalLabel"><?= h($title) ?></h3>
    </div>
    <?= $this->Form->create($model, ['onsubmit' => $onsubmit ?? null, 'style' => 'margin:0']) ?>
    <div class="modal-body modal-body-long">
        <p><?= h($description) ?></p>
        <?php
        echo $this->Form->input('relationship_type', [
            'type' => 'select',
            'options' => $options,
            'default' => $default ?? null,
        ]);
        echo $this->Form->input('relationship_type_custom', [
            'label' => __('Custom Relationship Type'),
            'default' => $default_custom ?? null,
        ]);
        // echo $this->Form->input('relationship_tag', [
        //     'label' => __('Tag Relationship Tag'),
        //     'default' => $default_tag ?? null,

        // ]);
        ?>
    </div>
    <div class="modal-footer">
        <button type="submit" class="btn btn-primary"><?= __('Submit') ?></button>
        <button type="button" class="btn btn-secondary cancel-button" data-dismiss="modal"><?= __('Cancel') ?></button>
    </div>
    <?= $this->Form->end() ?>
</div>

<script>
    $(document).ready(function() {
        function toggleCustomType() {
            if ($('#TagRelationshipType').val() == 'custom') {
                $('#TagRelationshipTypeCustom').parent().show()
            } else {
                $('#TagRelationshipTypeCustom').parent().hide()
            }
        }

        toggleCustomType()
        $('#TagRelationshipType').change(toggleCustomType)

    })
</script> -->

<?php
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => h($title),
        'model' => $model,
        'fields' => [
            [
                'field' => 'relationship_type',
                'type' => 'select',
                'options' => $options,
                'default' => $default ?? null,
                'stayInLine' => 1,
            ],
            [
                'field' => 'relationship_type_custom',
                'label' => __('Custom Relationship Type'),
                'default' => $default_custom ?? null,
            ],
            [
                'field' => 'relationship_tag_tags',
                'label' => __('Tag Relationship Tag'),
                'type' => 'tagsPicker',
                'default' => $default_tag_relationship_tag ?? null,
                'placeholder' => '["estimative-language:likelihood-probability=\"very-likely\""]',
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => $onsubmit ?? 'submitGenericFormInPlace();',
        ]
    ]
]);
if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'notification_settings'));
}

?>

<script>
    $(document).ready(function() {
        function toggleCustomType() {
            if ($('#TagRelationshipType').val() == 'custom') {
                $('#TagRelationshipTypeCustom').parent().show()
            } else {
                $('#TagRelationshipTypeCustom').parent().hide()
            }
        }

        toggleCustomType()
        $('#TagRelationshipType').change(toggleCustomType)

    })
</script>