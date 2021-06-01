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
                    'label' => __("For Intrusion Detection System"),
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
                array(
                    'field' => 'first_seen',
                    'type' => 'text',
                    'hidden' => true
                ),
                array(
                    'field' => 'last_seen',
                    'type' => 'text',
                    'hidden' => true
                ),
            ),
            'submit' => array(
                'action' => $action,
                'ajaxSubmit' => sprintf(
                    'submitPopoverForm(%s, %s, 0, 1)',
                    "'" . ($action === 'add' ? h($event['Event']['id']) : h($attribute['Attribute']['id'])) . "'",
                    "'" . h($action) . "'"
                )
            ),
            'metaFields' => array(
                '<div id="notice_message" style="display: none;"></div>',
                '<div id="bothSeenSliderContainer" style="height: 170px;"></div>'
            )
        )
    ));
    if (!$ajax) {
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'addAttribute', 'event' => $event));
    }
?>

<script type="text/javascript">
    var notice_list_triggers = <?php echo $notice_list_triggers; ?>;
    var category_type_mapping = <?php echo json_encode(array_map(function($value) {
        return array_combine($value['types'], $value['types']);
    }, $categoryDefinitions)); ?>;

    $('#AttributeDistribution').change(function() {
        checkSharingGroup('Attribute');
    });

    $('#AttributeCategory').change(function() {
        formCategoryChanged('Attribute');
        $('#AttributeType').chosen('destroy').chosen();
        if ($(this).val() === 'Internal reference') {
            $("#AttributeDistribution").val('0');
            checkSharingGroup('Attribute');
        }
    });

    $("#AttributeCategory, #AttributeType").change(function() {
        checkNoticeList('attribute');
    });

    $(function() {
        <?php
            if ($action == 'edit'):
        ?>
            checkNoticeList('attribute');
        <?php
            endif;
        ?>
        checkSharingGroup('Attribute');

        $('#AttributeType').closest('form').submit(function( event ) {
            if ($('#AttributeType').val() === 'datetime') {
                // add timezone of the browser if not set
                var allowLocalTZ = true;
                var $valueInput = $('#AttributeValue')
                var dateValue = moment($valueInput.val())
                if (dateValue.isValid()) {
                    if (dateValue.creationData().format !== "YYYY-MM-DDTHH:mm:ssZ" && dateValue.creationData().format !== "YYYY-MM-DDTHH:mm:ss.SSSSZ") {
                        // Missing timezone data
                        var confirm_message = '<?php echo __('Timezone missing, auto-detected as: ') ?>' + dateValue.format('Z')
                        confirm_message += '<?php echo '\r\n' . __('The following value will be submitted instead: '); ?>' + dateValue.toISOString(allowLocalTZ)
                        if (confirm(confirm_message)) {
                            $valueInput.val(dateValue.toISOString(allowLocalTZ));
                        } else {
                            return false;
                        }
                    }
                } else {
                    textStatus = '<?php echo __('Value is not a valid datetime. Expected format YYYY-MM-DDTHH:mm:ssZ') ?>'
                    showMessage('fail', textStatus);
                    return false;
                }
            }
        });

        <?php if (!$ajax): ?>
            $('#AttributeType').chosen();
            $('#AttributeCategory').chosen();
        <?php else: ?>
            $('#genericModal').on('shown', function() {
                $('#AttributeType').chosen();
                $('#AttributeCategory').chosen();
            })
        <?php endif; ?>
    });
</script>
<?php echo $this->element('form_seen_input'); ?>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
