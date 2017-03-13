<div class="popover_choice select_cluster">
	<legend>Select Cluster</legend>
	<div class="hidden">
		<?php
			echo $this->Form->create('Galaxy', array('url' => '/galaxies/attachClusterToEvent/' . $event_id, 'style' => 'margin:0px;'));
			echo $this->Form->input('target_id', array('type' => 'text'));
			echo $this->Form->end();
		?>
	</div>
	<div style="text-align:right;width:100%;" class="select_tag_search">
		<input id="clusterFilterField" style="width:100%;border:0px;padding:0px;" placeholder="search clusters..."/>
	</div>
	<div class="popover_choice_main" id ="popover_choice_main">
		<table style="width:100%;">
	<?php
		foreach ($clusters as $k => $cluster):
			$title = isset($cluster['description']) ? $cluster['description'] : $cluster['value'];
	?>
			<tr id="field_<?php echo h($cluster['id']); ?>" style="border-bottom:1px solid black;" class="templateChoiceButton filterableButton">
				<td class="clusterSelectChoice" data-event-id="<?php echo h($event_id); ?>" data-cluster-id="<?php echo h($cluster['id']); ?>" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" title="<?php echo 'Synonyms: ' . h($cluster['synonyms_string']); ?>"><?php echo h($cluster['value']); ?></td>
			</tr>
	<?php
		endforeach;
	?>
		<tr style="border-bottom:1px solid black;" class="templateChoiceButton">
			<td class="clusterSelectBack" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" data-event-id="<?php echo h($event_id); ?>" title="Select Galaxy">Back to Galaxy Selection</td>
		</tr>
		</table>
	</div>
	<div role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();">Cancel</div>
</div>
<script type="text/javascript">
	var lookup_table = <?php echo json_encode($lookup_table); ?>;
	$(document).ready(function() {
		resizePopoverBody();
		 $("#clusterFilterField").focus();
	});

	$('.clusterSelectBack').click(function() {
		getPopup($(this).data('event-id'), 'galaxies', 'selectGalaxy');
	});

	$('.clusterSelectChoice').click(function() {
		quickSubmitGalaxyForm($(this).data('event-id'), $(this).data('cluster-id'));
	});
	$('#clusterFilterField').keyup(function() {
		var filterString =  $("#clusterFilterField").val().toLowerCase();
		$('.filterableButton').hide();
		$.each(lookup_table, function(index, value) {
			var found = false;
			if (index.toLowerCase().indexOf(filterString) != -1) {
				$.each(value, function(k, v) {
					$('#field_' + v).show();
				});
			}
		});
	});
	$(window).resize(function() {
		resizePopoverBody();
	});
</script>
