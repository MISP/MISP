<div class="popover_choice">
	<legend>Select Tag</legend>
	<div style="display:none;">
		<?php
			if (isset($attributeTag)) {
				echo $this->Form->create('Attribute', array('url' => '/attributes/addTag/' . $object_id, 'style' => 'margin:0px;'));
			} else {
				echo $this->Form->create('Event', array('url' => '/events/addTag/' . $object_id, 'style' => 'margin:0px;'));
			}
			echo $this->Form->input('tag', array('value' => 0));
			echo $this->Form->end();
		?>
	</div>
	<div class="popover_choice_main" id ="popover_choice_main">
		<table style="width:100%;">
		<?php foreach ($options as $k => &$option): ?>
			<tr style="border-bottom:1px solid black;" class="templateChoiceButton">
				<?php if (isset($attributeTag)): ?>
				<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="quickSubmitAttributeTagForm('<?php echo h($object_id);?>', '<?php echo h($k); ?>');" title="<?php echo h($expanded[$k]);?>"><?php echo h($option); ?></td>
				<?php else: ?>
				<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="quickSubmitTagForm('<?php echo h($object_id);?>', '<?php echo h($k); ?>');" title="<?php echo h($expanded[$k]);?>"><?php echo h($option); ?></td>
				<?php endif; ?>
			</tr>
		<?php endforeach; ?>
		<tr style="border-bottom:1px solid black;" class="templateChoiceButton">
			<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($object_id); if (isset($attributeTag)) echo '/true'; ?>', 'tags', 'selectTaxonomy');" title="Select Taxonomy">Back to Taxonomy Selection</td>
		</tr>
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
