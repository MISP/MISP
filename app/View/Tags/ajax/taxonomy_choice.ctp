<div class="popover_choice  select_tag_source">
	<legend><?php echo __('Select Tag Source');?></legend>
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
				<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($object_id); ?>/all<?php if (isset($attributeTag)) echo '/true'; ?>', 'tags', 'selectTag');"><?php echo __('All Tags');?></td>
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
	});

	$(window).resize(function() {
		resizePopoverBody();
	});
</script>
