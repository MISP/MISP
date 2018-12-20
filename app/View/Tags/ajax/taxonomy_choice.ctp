<div class="popover_choice  select_tag_source">
    <legend><?php echo __('Select Tag Source');?></legend>
    <div style="text-align:right;width:100%;" class="select_tag_search">
        <input id="filterField" style="width:100%;border:0px;padding:0px;" placeholder="<?php echo __('search tags…');?>"/>
    </div>
    <div class="popover_choice_main" id ="popover_choice_main">
        <table style="width:100%;">
        <?php
            if ($favourites) {
                echo sprintf(
                    '<tr style="border-bottom:1px solid black;" class="templateChoiceButton">%s</tr>',
                    sprintf(
                        '<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%%;" onClick="getPopup(\'%s/favourites/%s\', \'tags\', \'selectTag\');">%s</td>',
                        h($object_id),
                        h($scope),
                        __('Favourite Tags')
                    )
                );
            }
            if ($scope !== 'tag_collection') {
                echo sprintf(
                    '<tr style="border-bottom:1px solid black;" class="templateChoiceButton">%s</tr>',
                    sprintf(
                        '<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%%;" onClick="getPopup(\'%s/collections/%s\', \'tags\', \'selectTag\');">%s</td>',
                        h($object_id),
                        h($scope),
                        __('Tag Collections')
                    )
                );
            }
            echo sprintf(
                '<tr style="border-bottom:1px solid black;" class="templateChoiceButton">%s</tr>',
                sprintf(
                    '<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%%;" onClick="getPopup(\'%s/0/%s\', \'tags\', \'selectTag\');">%s</td>',
                    h($object_id),
                    h($scope),
                    __('Custom Tags')
                )
            );
            echo sprintf(
                '<tr style="border-bottom:1px solid black;" class="templateChoiceButton">%s</tr>',
                sprintf(
                    '<td id="allTags" style="padding-left:10px;padding-right:10px; text-align:center;width:100%%;"  data-url="%s/all/%s" onClick="getPopup(this.getAttribute(\'data-url\') + $(\'#filterField\').val(), \'tags\', \'selectTag\');">%s</td>',
                    h($object_id),
                    h($scope),
                    __('All Tags')
                )
            );
            foreach ($options as $k => &$option) {
                echo sprintf(
                    '<tr style="border-bottom:1px solid black;" class="templateChoiceButton">%s</tr>',
                    sprintf(
                        '<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%%;" onClick="getPopup(\'%s/%s\', \'tags\', \'selectTag\');">%s: %s</td>',
                        h($object_id),
                        h($scope),
                        __('Taxonomy Library'),
                        h($option)
                    )
                );
            }
        ?>
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
