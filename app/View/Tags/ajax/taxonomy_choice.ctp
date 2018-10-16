<div class="popover_choice  select_tag_source">
    <legend><?php echo __('Select Tag Source');?></legend>
    <div style="text-align:right;width:100%;" class="select_tag_search">
        <input id="filterField" style="width:100%;border:0px;padding:0px;" placeholder="<?php echo __('search tags…');?>"/>
    </div>
    <div class="popover_choice_main" id ="popover_choice_main">
        <table style="width:100%;">
        <?php if ($favourites): ?>
            <tr style="border-bottom:1px solid black;" class="templateChoiceButton">
                <td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($object_id); ?>/favourites<?php if (isset($attributeTag)) echo '/true' ?>', 'tags', 'selectTag');"><?php echo __('Favourite Tags');?></td>
            </tr>
        <?php endif;?>
            <tr style="border-bottom:1px solid black;" class="templateChoiceButton">
                <td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($object_id); ?>/0<?php if (isset($attributeTag)) echo '/true'; ?>', 'tags', 'selectTag');"><?php echo __('Custom Tags');?></td>
            </tr>
            <tr style="border-bottom:1px solid black;" class="templateChoiceButton">
                <td id="allTags" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" data-url="<?php echo h($object_id); ?>/all<?php if (isset($attributeTag)) echo '/true/'; else echo '/false/'; ?>" onClick="getPopup(this.getAttribute('data-url') + $('#filterField').val(), 'tags', 'selectTag');"><?php echo __('All Tags');?></td>
            </tr>
        <?php foreach ($options as $k => &$option): ?>
            <tr style="border-bottom:1px solid black;" class="templateChoiceButton">
                <td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($object_id); ?>/<?php echo h($k); if (isset($attributeTag)) echo '/true'; ?>', 'tags', 'selectTag');"><?php echo __('Taxonomy Library');?>: <?php echo h($option); ?></td>
            </tr>
        <?php endforeach; ?>
        </table>
    </div>
    <div class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();"><?php echo __('Cancel');?></div>
</div>
<script type="text/javascript">
    $(document).ready(function() {
        resizePopoverBody();
        try {
            new Promise(function(resolve) { setTimeout(function() {$("#filterField").focus()}, 100)});
        } catch(error) {
            setTimeout(function() {$("#filterField").focus()}, 100);
        }
    });

    $(window).resize(function() {
        resizePopoverBody();
    });

    var lastKeyPressTimestamp = null;
    function onKeyUp() {
        lastKeyPressTimestamp = (new Date()).getTime();
        setTimeout(function() {
            if(lastKeyPressTimestamp + 400 < (new Date()).getTime()) {
                var filterString =  $("#filterField").val().toLowerCase();
                if(filterString.length > 0) {
                    $('#allTags').click();
                }
            }
        }, 500);
        
    }

    $('#filterField').keyup(onKeyUp);
</script>
