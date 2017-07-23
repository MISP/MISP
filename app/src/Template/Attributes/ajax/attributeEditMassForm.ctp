<div class="attributes">
<?php
	echo $this->Form->create('Attribute', array('url' => '/attributes/editSelected/' . $id));
?>
	<fieldset>
		<legend><?php echo __('Mass Edit Attributes'); ?></legend>
		<div id="formWarning" class="message ajaxMessage"></div>
		<div class="add_attribute_fields">
			<?php
			echo $this->Form->hidden('event_id', array('value' => $id));
			echo $this->Form->input('attribute_ids', array('style' => 'display:none;', 'label' => false));
			$distributionLevels[] = 'Do not alter current settings';
			echo $this->Form->input('distribution', array(
				'options' => array($distributionLevels),
				'label' => 'Distribution',
				'selected' => 6,
			));
			?>
				<div id="SGContainer" style="display:none;">
			<?php
				if (!empty($sgs)) {
					echo $this->Form->input('sharing_group_id', array(
							'options' => array($sgs),
							'label' => 'Sharing Group',
					));
				}
			?>
				</div>
			<?php
			echo $this->Form->input('to_ids', array(
					'options' => array('No', 'Yes', 'Do not alter current settings'),
					'data-content' => isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc'],
					'label' => 'For Intrusion Detection System',
					'selected' => 2,
			));
			?>
				<div class="input clear"></div>

				<div class="input clear"></div>
			<?php
			echo $this->Form->input('comment', array(
					'type' => 'textarea',
					'placeholder' => 'Leave this field empty to leave the comment field of the selected attributes unaltered.',
					'label' => 'Contextual Comment',
					'error' => array('escape' => false),
					'div' => 'input clear',
					'class' => 'input-xxlarge'
			));
			?>
			<div class="input clear"></div>
		</div>
	</fieldset>
	<p style="color:red;font-weight:bold;display:none;" id="warning-message">Warning: You are about to share data that is of a classified nature (Attribution / targeting data). Make sure that you are authorised to share this.</p>
		<div class="overlay_spacing">
			<table>
				<tr>
				<td style="vertical-align:top">
					<span id="submitButton" class="btn btn-primary" title="Submit" role="button" tabindex="0" aria-label="Submit" onClick="submitPopoverForm('<?php echo $id;?>', 'massEdit')">Submit</span>
				</td>
				<td style="width:540px;">&nbsp;</td>
				<td style="vertical-align:top;">
					<span class="btn btn-inverse" title="Cancel" role="button" tabindex="0" aria-label="Cancel" id="cancel_attribute_add">Cancel</span>
				</td>
				</tr>
			</table>
		</div>
	<?php
		echo $this->Form->end();
	?>
</div>

<script type="text/javascript">

//
// Generate tooltip information
//
var formInfoValues = new Array();
var fieldsArrayAttribute = new Array('AttributeDistribution', 'AttributeComment', 'AttributeToIds');
<?php
foreach ($distributionDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
}
?>

$(document).ready(function() {

	$('#AttributeDistribution').change(function() {
		if ($('#AttributeDistribution').val() == 4) $('#SGContainer').show();
		else $('#SGContainer').hide();
	});

	$('#AttributeAttributeIds').attr('value', getSelected());

	$("#Attribute, #AttributeDistribution").on('mouseover', function(e) {
		var $e = $(e.target);
		if ($e.is('option')) {
			$('#'+e.currentTarget.id).popover('destroy');
			$('#'+e.currentTarget.id).popover({
				trigger: 'focus',
				placement: 'right',
				container: 'body',
				content: formInfoValues[$e.val()],
			}).popover('show');
		}
	});

	$("input, label").on('mouseleave', function(e) {
		$('#'+e.currentTarget.id).popover('destroy');
	});

	$("input, label").on('mouseover', function(e) {
		var $e = $(e.target);
		$('#'+e.currentTarget.id).popover('destroy');
		$('#'+e.currentTarget.id).popover({
			trigger: 'focus',
			placement: 'right',
			container: 'body',
		}).popover('show');
	});

	// workaround for browsers like IE and Chrome that do now have an onmouseover on the 'options' of a select.
	// disadvangate is that user needs to click on the item to see the tooltip.
	// no solutions exist, except to generate the select completely using html.
	$("#Attribute, #AttributeDistribution").on('change', function(e) {
		var $e = $(e.target);
		$('#'+e.currentTarget.id).popover('destroy');
		$('#'+e.currentTarget.id).popover({
			trigger: 'focus',
			placement: 'right',
			container: 'body',
			content: formInfoValues[$e.val()],
		}).popover('show');
	});
	$('#cancel_attribute_add').click(function() {
		$('#gray_out').fadeOut();
		$('#popover_form').fadeOut();
	});
});

</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
