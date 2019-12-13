<?php
    $modelForForm = 'Attribute';
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => $action === 'add' ? __('Add Attribute') : __('Edit Attribute'),
            'model' => $modelForForm,
            'fields' => array(
                array(
                    'field' => 'event_id',
                    'class' => 'org-id-picker-hidden-field',
                    'type' => 'text',
                    'hidden' => true
                ),
                array(
                    'field' => 'category',
                    'class' => 'input',
                    'empty' => __('(choose one)'),
                    'options' => $categories,
                    'stayInLine' => 1
                ),
                array(
                    'field' => 'type',
                    'class' => 'input',
                    'empty' => __('(choose category first)'),
                    'options' => $types
                ),
                array(
                    'field' => 'distribution',
                    'class' => 'input',
                    'options' => $distributionLevels,
                    'default' => isset($attribute['Attribute']['distribution']) ? $attribute['Attribute']['distribution'] : $initialDistribution,
                    'stayInLine' => 1
                ),
                array(
                    'field' => 'sharing_group_id',
                    'class' => 'input',
                    'options' => $sharingGroups,
                    'label' => __("Sharing Group")
                ),
                array(
                    'field'=> 'value',
                    'type' => 'textarea',
                    'class' => 'input span6',
                    'div' => 'input clear'
                ),
                array(
                    'field' => 'comment',
                    'type' => 'text',
                    'class' => 'input span6',
                    'div' => 'input clear',
                    'label' => __("Contextual Comment")
                ),
                array(
                    'field' => 'to_ids',
                    'type' => 'checkbox',
                    'label' => __("for Intrusion Detection System"),
                    //'stayInLine' => 1
                ),
                array(
                    'field' => 'batch_import',
                    'type' => 'checkbox'
                ),
                array(
                    'field' => 'disable_correlation',
                    'type' => 'checkbox'
                ),
                '<div id="extended_event_preview" style="width:446px;"></div>'
            ),
            'submit' => array(
                'action' => $action,
                'ajaxSubmit' => sprintf(
                    'submitPopoverForm(%s, %s, 0, 1)',
                    "'" . ($action == 'add' ? h($event_id) : h($attribute['Attribute']['id'])) . "'",
                    "'" . h($action) . "'"
                )
            )
        )
    ));
    if (!$ajax) {
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => $this->action === 'add' ? 'add' : 'editEvent'));
    }
?>

<script type="text/javascript">
    var notice_list_triggers = <?php echo $notice_list_triggers; ?>;
    var composite_types = <?php echo json_encode($compositeTypes); ?>;
    var category_type_mapping = new Array();

    <?php
    foreach ($categoryDefinitions as $category => $def) {
        echo "category_type_mapping['" . addslashes($category) . "'] = {";
        $first = true;
        foreach ($def['types'] as $type) {
            if ($first) {
                $first = false;
            } else {
                echo ', ';
            }
            echo "'" . addslashes($type) . "' : '" . addslashes($type) . "'";
        }
        echo "}; \n";
    }
    ?>

    $('#AttributeDistribution').change(function() {
        checkSharingGroup('Attribute');
    });

    $('#AttributeCategory').change(function() {
        formCategoryChanged('Attribute');
        if ($(this).val() === 'Internal reference') {
            $("#AttributeDistribution").val('0');
            checkSharingGroup('Attribute');
        }
    });

    $("#AttributeCategory, #AttributeType").change(function() {
        checkNoticeList('attribute');
    });

    $(document).ready(function() {
        <?php
            if ($action == 'edit'):
        ?>
            checkNoticeList('attribute');
        <?php
            endif;
        ?>
        checkSharingGroup('Attribute');
    });
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
