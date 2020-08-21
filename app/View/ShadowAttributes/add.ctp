<?php
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'title' => __('Add Proposal'),
        'model' => 'ShadowAttribute',
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
            'action' => 'add',
            'text' => __('Propose'),
            'ajaxSubmit' => sprintf(
                'submitPopoverForm(%s, %s, 0, 1)',
                "'" . h($event_id) . "'",
                "'add'"
            )
        ),
        'metaFields' => array(
            '<div id="bothSeenSliderContainer" style="height: 170px;"></div>'
        )
    )
));
if (!$ajax) {
    $event = ['Event' => ['id' => $event_id ]];
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'proposeAttribute', 'event' => $event));
}
?>
    <script type="text/javascript">
        var category_type_mapping = <?= json_encode(array_map(function($value) {
            return array_combine($value['types'], $value['types']);
        }, $categoryDefinitions)); ?>;

        $('#ShadowAttributeCategory').change(function() {
            formCategoryChanged('ShadowAttribute');
            $('#ShadowAttributeType').chosen('destroy').chosen();
        });

        $(function() {
            $('#ShadowAttributeType').closest('form').submit(function( event ) {
                if ($('#ShadowAttributeType').val() === 'datetime') {
                    // add timezone of the browser if not set
                    var allowLocalTZ = true;
                    var $valueInput = $('#ShadowAttributeValue')
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
                        var textStatus = '<?php echo __('Value is not a valid datetime. Expected format YYYY-MM-DDTHH:mm:ssZ') ?>'
                        showMessage('fail', textStatus);
                        return false;
                    }
                }
            });

            <?php if (!$ajax): ?>
            $('#ShadowAttributeType').chosen();
            $('#ShadowAttributeCategory').chosen();
            <?php else: ?>
            $('#genericModal').on('shown', function() {
                $('#ShadowAttributeType').chosen();
                $('#ShadowAttributeCategory').chosen();
            })
            <?php endif; ?>
        });
    </script>
<?php echo $this->element('form_seen_input'); ?>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
