<div class="populate_from_template form">
<?php echo $this->Form->create('', array('type' => 'file'));?>
    <fieldset>
        <div id="populate_template_info" class="templateTableRow templateTableRow80">
            <?php
                echo $this->element('templateElements/populateTemplateDescription');
            ?>
        </div>
        <?php
            $first = true;
            foreach ($templateData['TemplateElement'] as $k => $element) {
                if ($k != 0 && (($k == count($templateData['TemplateElement'])) || !$first && $element['element_definition'] == 'text')):

                ?>
                    </div>
                <?php
                endif;
                if ($element['element_definition'] == 'text' || $first || $k == count($templateData['TemplateElement'])):
                $first = false;
                ?>
                    <div class="templateTableRow templateTableRow80">
                <?php
                endif;
                echo $this->element('templateElements/populateTemplate' . ucfirst($element['element_definition']), array('element' => $element['TemplateElement' . ucfirst($element['element_definition'])][0], 'k' => $k, 'element_id' => $element['id'], 'value' => ''));
            }
            echo $this->Form->input('fileArray', array(
                'label' => false,
                'style' => 'display:none;',
                'value' => '[]',
            ));
        ?>
    </fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'populateFromtemplate', 'event' => array('Event' => array('id' => $event_id)), 'template_id' => $template_id));
?>
<?php
    if (!empty($fileArray)) {
        $fileArray = json_decode($fileArray, true);
        foreach ($fileArray as $k => $v) {
            $fileArray[$k] = array(
                'filename' => h($v['filename']),
                'tmp_name' => h($v['tmp_name']),
                'element_id' => h($v['element_id']),
            );
        }
        $fileArray = json_encode($fileArray);
    }
?>
<script type="text/javascript">
$(document).ready(function() {
    <?php if (!empty($fileArray)): ?>
        populateTemplateHiddenFileDiv(<?php echo $fileArray; ?>);
    <?php endif; ?>
    populateTemplateFileBubbles();
});
</script>
