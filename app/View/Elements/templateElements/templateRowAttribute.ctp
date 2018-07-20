<li id="id_<?php echo $element_id; ?>" class="templateTableRow">
    <div class="templateElementHeader" style="width:100%; position:relative;">
        <div class="templateGlass"></div>
        <div class ="templateElementHeaderText"><?php echo __('Attribute');?></div>
    </div>
    <table style="width:100%">
        <tr>
            <td>
                <div style="display:inline">
                    <div class="templateTableTDName templateTableArea">
                        <div class="templateTableColumnName">
                            <?php echo __('Name');?>
                        </div>
                        <div class="">
                            <?php echo h($element['TemplateElementAttribute'][0]['name']); ?>&nbsp;
                        </div>
                    </div>

                    <div class="templateTableTDDescription templateTableArea">
                        <div class="templateTableColumnName">
                            <?php echo __('Description');?>
                        </div>
                        <div class="">
                            <?php echo h($element['TemplateElementAttribute'][0]['description']); ?>&nbsp;
                        </div>
                    </div>

                    <div class="templateTableTDCategory templateTableArea">
                        <div class="templateTableColumnName">
                            <?php echo __('Category');?>
                        </div>
                        <div class="">
                            <?php echo h($element['TemplateElementAttribute'][0]['category']); ?>&nbsp;
                        </div>
                    </div>

                    <div class="templateTableTDTypes templateTableArea">
                        <div class="templateTableColumnName">
                            <?php echo __('Types');?>
                        </div>
                        <div class="">
                            <?php
                                if ($element['TemplateElementAttribute'][0]['complex']) {
                                    echo '<span style="color:red">' . h($element['TemplateElementAttribute'][0]['type']) . '</span> (';
                                    foreach ($validTypeGroups[$element['TemplateElementAttribute'][0]['type']]['types'] as $k => $t) {
                                        if ($k != 0) echo ', ';
                                        echo h($t);
                                    }
                                    echo ')';
                                } else {
                                    echo h($element['TemplateElementAttribute'][0]['type']);
                                }
                            ?>&nbsp;
                        </div>
                    </div>

                    <div class="templateTableTDShort templateTableArea">
                        <div class="templateTableColumnName">
                            <?php echo __('Mandatory');?>
                        </div>
                        <div class="">
                            <?php
                                if ($element['TemplateElementAttribute'][0]['mandatory']) echo __('Yes');
                                else echo __('No');
                            ?>&nbsp;
                        </div>
                    </div>
                    <div class="templateTableTDShort templateTableArea">
                        <div class="templateTableColumnName">
                            <?php echo __('Batch');?>
                        </div>
                        <div class="">
                            <?php
                                if ($element['TemplateElementAttribute'][0]['batch']) echo __('Yes');
                                else echo __('No');
                            ?>&nbsp;
                        </div>
                    </div>

                    <div class="templateTableTDShort templateTableArea">
                        <div class="templateTableColumnName">
                            <?php echo __('IDS');?>
                        </div>
                        <div class="">
                            <?php
                                if ($element['TemplateElementAttribute'][0]['to_ids']) echo __('Yes');
                                else echo __('No');
                            ?>&nbsp;
                        </div>
                    </div>

                    <div class="templateTableTDActions templateTableArea">
                        <div class="templateTableColumnName">
                            <?php echo __('Actions');?>
                        </div>
                        <div class="">
                            <?php
                                if ($mayModify) {
                                    echo $this->Form->create('TemplateElement', array('class' => 'inline-delete', 'style' => 'display:inline-block;', 'id' => 'TemplateElement_' . h($element_id) . '_delete', 'url' => array('action' => 'delete')));
                            ?>
                                    <span class="icon-trash useCursorPointer" title="<?php echo __('Delete template element');?>" role="button" tabindex="0" aria-label="<?php echo __('Delete template element');?>" onClick="deleteObject('template_elements', 'delete' ,'<?php echo h($element_id); ?>', '<?php echo h($element['TemplateElement']['template_id']); ?>');"></span>
                            <?php
                                    echo $this->Form->end();
                            ?>
                                    <span class="icon-edit useCursorPointer" title="<?php echo __('Edit template element');?>" role="button" tabindex="0" aria-label="<?php echo __('Edit template element');?>" onClick="editTemplateElement('attribute' ,'<?php echo h($element_id); ?>');"></span>
                            <?php
                                } else {
                                    echo '&nbsp;';
                                }
                            ?>
                        </div>
                    </div>
                </div>
            </td>
        </tr>
    </table>
</li>
