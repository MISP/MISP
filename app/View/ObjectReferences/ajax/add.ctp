<div class="popover_choice">
    <?php echo $this->Form->create('ObjectReference', array('url' => $baseurl . '/objectReferences/add/' . $objectId));?>
    <fieldset>
        <legend><?php echo __('Add Object Reference'); ?></legend>
            <div class="overlay_spacing">
                <div class="row-fluid">
                    <div class="span6">
                        <?php
                            echo $this->Form->input('relationship_type_select', array(
                                'label' => __('Relationship type'),
                                'options' => $relationships,
                                'style' => 'width:334px;',
                                'div' => false
                            ));
                        ?>
                        <div class="hidden">
                            <label for="ObjectReferenceRelationshipTypeSelect"><?php echo __('Relationship type');?></label>
                            <?php
                                echo $this->Form->input('relationship_type', array(
                                    'label' => false,
                                    'style' => 'width:320px;',
                                    'div' => false
                                ));
                            ?>
                        </div>
                    </div>
                    <div class="span6">
                        <?php
                            echo $this->Form->input('comment', array(
                                'label' => __('Comment'),
                                'rows' => 1,
                                'style' => 'width:320px;height:20px !important;'
                            ));
                        ?>
                    </div>
                </div>
                <div class="input clear"></div>
                <div class="row-fluid">
                    <div class="span6">
                        <?php
                            echo $this->Form->input('referenced_uuid', array(
                                'label' => __('Target UUID'),
                                'div' => false,
                                'style' => 'width:320px;'
                            ));
                        ?>
                        <br>

                        <?php
                            $items = array();
                            if (!empty($event['Object'])){
                                foreach ($event['Object'] as $object) {
                                    $combinedFields = sprintf('%s/%s/%s',
                                        __('Object'),
                                        h($object['meta-category']),
                                        h($object['name'])
                                    );

                                    $attributes = array();
                                    $attributesValues = array();
                                    foreach ($object['Attribute'] as $attribute) {
                                        $combinedFields .= '/' . h($attribute['value']);
                                        $attributesValues[] = h($attribute['value']);
                                        $attributes[] = h($attribute['value']);
                                        $combinedFields .= '/' . h($attribute['id']);
                                    }
                                    $attributesValues = implode(', ', $attributesValues);
                                    $items[] = array(
                                        'name' => $combinedFields,
                                        'value' => h($object['uuid']),
                                        'additionalData' => array(
                                            'type' => 'Object'
                                        ),
                                        'template' => array(
                                            'name' => $object['name'],
                                            'preIcon' => 'fa-th-large',
                                            'infoExtra' => $attributesValues,
                                            'infoContextual' => $object['meta-category']
                                        )
                                    );
                                }
                            }
                            if (!empty($event['Attribute'])) {
                                foreach ($event['Attribute'] as $attribute) {
                                    $combinedFields = sprintf('%s/%s/%s/%s/%s',
                                        __('Attribute'),
                                        h($attribute['category']),
                                        h($attribute['type']),
                                        h($attribute['value']),
                                        h($attribute['id'])
                                    );
                                    $items[] = array(
                                        'name' => $combinedFields,
                                        'value' => h($attribute['uuid']),
                                        'additionalData' => array(
                                            'type' => 'Attribute'
                                        ),
                                        'template' => array(
                                            'name' => $attribute['value'],
                                            'infoExtra' => array(
                                                'type' => 'check',
                                                'checked' => $attribute['to_ids'],
                                                'text' => 'ids'
                                            ),
                                            'infoContextual' => $attribute['category'] . ' :: ' . $attribute['type'],
                                        ),
                                    );
                                }
                            }
                            $options = [
                                'functionName' => 'changeObjectReferenceSelectOption',
                                'select_threshold' => 0,
                                'chosen_options' => ['width' => '334px'],
                                'select_options' => ['data-targetselect' => 'targetSelect'],
                                'disabledSubmitButton' => true,
                            ];
                            echo $this->element('generic_picker', ['items' => $items, 'options' => $options]);
                        ?>
                    </div>
                    <div class="span6">
                        <label for="selectedData"><?php echo __('Target Details');?></label>
                        <div class="greyHighlightedBlock" id="targetData">
                            &nbsp;
                        </div>
                    </div>
                </div>
                <div>
                    <table style="margin-bottom:5px;">
                        <tr>
                            <td>
                                <span id="submitButton" class="btn btn-primary" title="<?php echo __('Submit');?>" role="button" tabindex="0" aria-label="<?php echo __('Submit');?>" onClick="submitPopoverForm('<?php echo h($objectId); ?>', 'addObjectReference')"><?php echo __('Submit');?></span>
                            </td>
                            <td style="width:100%;">&nbsp;</td>
                            <td>
                                <span class="btn btn-inverse" title="<?php echo __('Cancel');?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" onClick="cancelPopoverForm();"><?php echo __('Cancel');?></span>
                            </td>
                        </tr>
                    </table>
                </div>
            <?php
                echo $this->Form->end();
            ?>
        </div>
    </fieldset>
</div>
<script>
    var targetEvent = <?php echo json_encode($event); ?>;
    $(function() {
        $('#ObjectReferenceReferencedUuid').on('input', function() {
            objectReferenceInput();
        });
        $("#ObjectReferenceRelationshipTypeSelect").change(function() {
            objectReferenceCheckForCustomRelationship();
        }).chosen({ width: "100%" });
    });
</script>
