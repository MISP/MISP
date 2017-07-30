<div class="popover_choice  select_galaxy_source">
	<legend>Select Cluster Source</legend>
	<div class="popover_choice_main" id ="popover_choice_main">
		<table style="width:100%;">
			<tr style="border-bottom:1px solid black;" class="templateChoiceButton">
				<td role="button" tabindex="0" aria-label="All clusters" title="All clusters" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($event_id); ?>/0', 'galaxies', 'selectCluster');">All Galaxies</td>
			</tr>
		<?php foreach ($galaxies as $galaxy): ?>
			<tr style="border-bottom:1px solid black;" class="templateChoiceButton">
				<td role="button" tabindex="0" aria-label="<?php echo h($galaxy['Galaxy']['name']); ?>" title="<?php echo h($galaxy['Galaxy']['name']); ?>" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($event_id); ?>/<?php echo h($galaxy['Galaxy']['id']);?>', 'galaxies', 'selectCluster');">Galaxy: <?php echo h($galaxy['Galaxy']['name']); ?></td>
			</tr>
		<?php endforeach; ?>
		</table>
	</div>
	<div role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();">Cancel</div>
</div>
<script type="text/javascript">
	$(document).ready(function() {
		resizePopoverBody();
	});

	$(window).resize(function() {
		resizePopoverBody();
	});
</script>
