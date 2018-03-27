<div class="popover_choice  select_galaxy_source">
	<legend><?php echo __('Select Cluster Source');?></legend>
	<div class="popover_choice_main" id ="popover_choice_main">
		<table style="width:100%;">
			<tr  class="templateChoiceButton">
				<td role="button" tabindex="0" aria-label="<?php echo __('All clusters');?>" title="<?php echo __('All clusters');?>" style="padding-left:10px;padding-right:10px;width:100%;" onClick="getPopup('<?php echo h($event_id); ?>/0', 'galaxies', 'selectCluster');"><?php echo __('All Galaxies');?></td>
			</tr>
		<?php foreach ($galaxies as $galaxy): ?>
			<tr  class="templateChoiceButton">
				<td role="button" tabindex="0" aria-label="<?php echo h($galaxy['Galaxy']['name']); ?>" title="<?php echo h($galaxy['Galaxy']['name']); ?>" style="padding-left:10px;padding-right:10px;width:100%;" onClick="getPopup('<?php echo h($event_id); ?>/<?php echo h($galaxy['Galaxy']['id']);?>', 'galaxies', 'selectCluster');">Galaxy: <?php echo h($galaxy['Galaxy']['name']); ?></td>
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

	$(window).resize(function() {
		resizePopoverBody();
	});
</script>
