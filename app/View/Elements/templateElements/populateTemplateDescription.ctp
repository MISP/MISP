<div id="populate_template_info_header" class="templateElementHeader" style="width:100%; position:relative;">
    <div class="templateGlass"></div>
    <div class ="templateElementHeaderText"><?php echo __('Template Description');?></div>
</div>
<div id="populate_template_info_body" class="populate_template_div_body">
    <div class="left" style="float:left;"><?php echo __('Template ID');?>:</div>
    <div class="right" style="float:left;"><?php echo h($templateData['Template']['id']); ?></div><br />
    <div class="left" style="float:left;"><?php echo __('Template Name');?>:</div>
    <div class="right" style="float:left;"><?php echo h($templateData['Template']['name']); ?></div><br />
    <div class="left" style="float:left;"><?php echo __('Created by');?>:</div>
    <div class="right" style="float:left;"><?php echo h($templateData['Template']['org']); ?></div><br />
    <div class="left" style="float:left;"><?php echo __('Description');?>:</div>
    <div class="right" style="float:left;"><?php echo h($templateData['Template']['description']); ?></div><br />
    <div class="left" style="float:left;"><?php echo __('Tags automatically assigned');?>:</div>
    <div class="right" style="float:left;">
        <?php
            foreach ($templateData['TemplateTag'] as $tag) {
                echo $this->element('ajaxTemplateTag', array('editable' => 'no', 'tag' => array('Tag' => $tag['Tag'])));
            }
        ?>
    </div>
</div>
