<div class="popover_choice">
    <legend><?php echo __('Choose the format that you wish to download the search results in'); ?></legend>
    <div class="popover_choice_main" id ="popover_choice_main">
        <table style="width:100%;">
        <?php
			foreach ($exports as $k => $export) {
				$tr = 'style="border-bottom:1px solid black;" class="templateChoiceButton"';
				$td = sprintf(
					'class="" tabindex="0" title="%s" style="%s" data-type="%s"',
					__('Export as %s', h($export)),
					'padding-left:10px; text-align:center;width:100%;',
					h($export)
				);
				$div = '<div style="height:100%;width:100%;">' . h($export) . '</div>';
				$a = sprintf(
					'<a href="%s" style="%s" download>%s</a>',
					$baseurl . '/attributes/exportSearch/' . h($export),
					'color: black; text-decoration: none;',
					$div
				);
				$td = sprintf(
					'<td class="export_choice_button" tabindex="0" title="%s", style="%s">%s</td>',
					__('Export as %s', h($export)),
					'padding-left:10px; text-align:center;width:100%;',
					$a
				);
				echo sprintf('<tr %s>%s</tr>', $tr, $td);
			}
		?>
        </table>
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
