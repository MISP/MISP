<li id="id_<?php echo $element_id;?>" class="templateTableRow">
    <div class="templateElementHeader" style="width:100%; position:relative;">
        <div class="templateGlass"></div>
        <div class ="templateElementHeaderText"><?php echo __('Text');?></div>
    </div>
    <table class="templateTable">
        <tr>
            <td>
                <div style="display:inline">
                    <div class="templateTableTDName templateTableArea">
                        <div class="templateTableColumnName">
                            <?php echo __('Name');?>
                        </div>
                        <div class="">
                            <?php echo h($element['TemplateElementText'][0]['name']); ?>&nbsp;
                        </div>
                    </div>
                    <div class="templateTableTDText templateTableArea">
                        <div class="templateTableColumnName">
                            <?php echo __('Text');?>
                        </div>
                        <div class="">
                            <?php echo h($element['TemplateElementText'][0]['text']); ?>&nbsp;
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
                                    <span class="icon-edit useCursorPointer" title="<?php echo __('Edit template element');?>" role="button" tabindex="0" aria-label="<?php echo __('Edit template element');?>" onClick="editTemplateElement('text' ,'<?php echo h($element_id); ?>');"></span>
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
