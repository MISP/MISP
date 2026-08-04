<div class="popover_choice">
    <legend><?php echo __('Choose the format that you wish to download the event in'); ?></legend>
    <div class="popover_choice_main" id ="popover_choice_main">
        <table style="width:100%;">
        <?php foreach ($exports as $k => $export): ?>
            <tr
                style="border-bottom:1px solid black;"
                class="templateChoiceButton"
                data-export-url="<?php echo h($export['url']); ?>"
                data-export-key="<?php echo h($k); ?>"
                data-export-checkbox="<?php echo h($export['checkbox']); ?>"
            >
                <td
                    class="export_choice_button"
                    role="button"
                    tabindex="0"
                    aria-label= "<?php echo __('Export as %s', h($export['text']));?>"
                    title="<?php echo __('Export as %s', h($export['text']));?>"
                    style="padding-left:10px; text-align:left;width:50%;"
                >
                    <?php echo h($export['text']); ?>
                </td>
                <td
                    class="export_choice_button"
                    role="button"
                    tabindex="0"
                    aria-label= "<?php echo __('Export as %s', h($export['text']));?>"
                    title="<?php echo __('Export as %s', h($export['text']));?>"
                    class="export_choice_button"
                    style="padding-right:10px; width:50%;text-align:right;"
                >
                    <?php if ($export['checkbox']):
                        echo h($export['checkbox_text']);
                    ?>
                        <input
                            title="<?php h($export['checkbox_text']); ?>"
                            id="<?php echo h($k) . '_toggle';?>"
                            type="checkbox"
                            style="align;vertical-align:top;margin-top:8px;"
                            <?php if (isset($export['checkbox_default'])) echo 'checked';?>
                        >
                        <span id ="<?php echo h($k);?>_set" style="display:none;"><?php if (isset($export['checkbox_set'])) echo h($export['checkbox_set']); ?></span>
                    <?php else: ?>
                        &nbsp;
                    <?php endif; ?>
                </td>
            </tr>
        <?php endforeach; ?>
        </table>
    </div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();"><?php echo __('Cancel');?></div>
</div>
<script type="text/javascript">
    $(document).ready(function() {
        resizePopoverBody();
    });
    $('.export_choice_button').click(function (e) {
        exportChoiceSelect(e);
    });

    $(window).resize(function() {
        resizePopoverBody();
    });
</script>
