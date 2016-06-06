<div class="popover_choice">
	<legend>Select Tag Source</legend>
	<div class="popover_choice_main" id ="popover_choice_main">
		<table style="width:100%;">
		<?php if ($favourites): ?>
			<tr style="border-bottom:1px solid black;" class="templateChoiceButton">
				<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($event_id); ?>/favourites', 'tags', 'selectTag');">Favourite Tags</td>
			</tr>
		<?php endif;?>
			<tr style="border-bottom:1px solid black;" class="templateChoiceButton">
				<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($event_id); ?>/0', 'tags', 'selectTag');">Custom Tags</td>
			</tr>
		<?php foreach ($options as $k => &$option): ?>
			<tr style="border-bottom:1px solid black;" class="templateChoiceButton">
				<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($event_id); ?>/<?php echo h($k);?>', 'tags', 'selectTag');">Taxonomy Library: <?php echo h($option); ?></td>
			</tr>
		<?php endforeach; ?>
		</table>
	</div>
	<div class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();">Cancel</div>
</div>
<script type="text/javascript">
	$(document).ready(function() {
		resizePopoverBody();
	});

	$(window).resize(function() {
		resizePopoverBody();
	});
</script>
