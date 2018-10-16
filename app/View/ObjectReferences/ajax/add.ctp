<div class="popover_choice">
        <?php echo $this->Form->create('ObjectReference', array('url' => '/objectReferences/add/' . $objectId));?>
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
                            <div id="" class="hidden">
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
                            <br />
                            <select id="targetSelect" size="10" style="width:100%;height:200px;">
                                <?php
                                    if (!empty($event['Object'])):
                                        foreach ($event['Object'] as $object):
                                ?>
                                            <option class="selectOption" value="<?php echo h($object['uuid']);?>" data-type="Object"><?php echo __('Object');?>: <?php echo h($object['meta-category']) . '/' . h($object['name']); ?></option>
                                <?php
                                        endforeach;
                                    endif;
                                    if (!empty($event['Attribute'])):
                                        foreach ($event['Attribute'] as $attribute):
                                ?>
                                            <option class="selectOption" value="<?php echo h($attribute['uuid']);?>" data-type="Attribute"><?php echo __('Attribute');?>: <?php echo h($attribute['category']) . '/' . h($attribute['type']); ?></option>
                                <?php
                                        endforeach;
                                    endif;
                                ?>
                            </select>
                        </div>
                        <div class="span6">
                            <label for="selectedData"><?php echo __('Target Details');?></label>
                            <div class="redHighlightedBlock" id="targetData">
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
</div>
<script type="text/javascript">
    var targetEvent = <?php echo json_encode($event); ?>;
    $(document).ready(function() {
        $('#ObjectReferenceUuid').on('input', function() {
            objectReferenceInput();
        });
        $(".selectOption").click(function() {
            changeObjectReferenceSelectOption();
        });
        $("#ObjectReferenceRelationshipTypeSelect").change(function() {
            objectReferenceCheckForCustomRelationship();
        });
    });
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
