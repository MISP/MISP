<div class="popover_choice">
	<legend>Select Tag</legend>
	<div style="display:none;">
		<?php
			echo $this->Form->create('Event', array('url' => '/events/addTag/' . $event_id, 'style' => 'margin:0px;'));
			echo $this->Form->input('tag', array('value' => 0));
			echo $this->Form->end();
		?>
	</div>
	<div style="width:100%;">
		<input id="filterField" style="width:98%;border:0px;padding:0px;margin:4px 1% 4px 1%;text-align: center;height: 23px;border: 1px solid #cccccc;box-shadow: 0 1px 1px rgba(0, 0, 0, 0.075) inset;" placeholder="search tags.."/>
	</div>
	<div class="popover_choice_main" id ="popover_choice_main">
		<table class="popover_choice_table">
		<?php foreach ($options as $k => &$option): ?>
			<tr id="field_<?php echo h($k); ?>" style="border-bottom:1px solid black;background-color: #eee;" class="templateChoiceButton">
				<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="quickSubmitTagForm('<?php echo h($event_id);?>', '<?php echo h($k); ?>');" title="<?php echo h($expanded[$k]);?>"><?php echo h($option); ?></td>
			</tr>
		<?php endforeach; ?>
		<tr style="border-bottom:1px solid black;" class="templateChoiceButton">
			<td style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" onClick="getPopup('<?php echo h($event_id);?>', 'tags', 'selectTaxonomy');" title="Select Taxonomy">Back to Taxonomy Selection</td>
		</tr>
		</table>
	</div>
	<div class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();">Cancel</div>
</div>
<script type="text/javascript">
	var tags = <?php echo json_encode($options); ?>;
	$(document).ready(function() {
		resizePopoverBody();
		 $("#filterField").focus();
	});
	
	$('#filterField').keyup(function() {
		var filterString =  $("#filterField").val().toLowerCase();
		$.each(tags, function(index, value) {
			if (value.toLowerCase().indexOf(filterString) == -1) {
				$('#field_' + index).hide();
			} else {
				$('#field_' + index).show();
			}
		});
	});
	
	$(window).resize(function() {
		resizePopoverBody();
	});
</script>
