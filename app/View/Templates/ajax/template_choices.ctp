<div class="popover_choice">
    <legend><?php echo __('Choose element type'); ?></legend>
    <div class="popover_choice_main" id ="popover_choice_main">
        <?php foreach ($templates as $k => $template): ?>
            <div role="button" tabindex="0" aria-label="<?php echo h($template['Template']['description']); ?>" class="templateChoiceButton" style="width:100%;" title="<?php echo h($template['Template']['description']); ?>" onClick="document.location.href ='<?php echo $baseurl;?>/templates/populateEventFromTemplate/<?php echo h($template['Template']['id']);?>/<?php echo h($id); ?>'">
                <div style="float:left;">
                <?php
                    echo $this->OrgImg->getOrgImg(array('name' => $template['Template']['org'], 'size' => 24));
                ?>
                </div>
                <div><span style="position:relative;left:-12px;"><?php echo h($template['Template']['name']);?>&nbsp;</span></div>
            </div>
        <?php endforeach; ?>
    </div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();"><?php echo __('Cancel');?></div>
</div>
<script type="text/javascript">
$(document).ready(function() {
    resizePopoverBody();
});

$(window).resize(function() {
    resizePopoverBody();
});
</script>
