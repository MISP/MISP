<div class="attribute_replace">
<?php
echo $this->Form->create('Attribute', array('id', 'url' => '/attributes/attributeReplace/' . $event_id));
?>
	<fieldset>
		<legend><?php echo __('Attribute Replace Tool'); ?></legend>
		<div class="add_attribute_fields">
		<p>Choose a category and a type, then paste a list of IOCs that match the selection into the field below. This will delete all of the attributes not found in the new inserted list, whilst creating the attributes that are in the new list but don't exist as attributes. Found matches will be left untouched.</p>
			<?php
			echo $this->Form->hidden('event_id');
			echo $this->Form->input('category', array(
					'empty' => '(choose one)'
			));
			echo $this->Form->input('type', array(
					'empty' => '(first choose category)'
			));
			echo $this->Form->input('to_ids', array(
					'type' => 'checkbox',
					'label' => 'Mark all new attributes as to IDS',
			));
			echo $this->Form->input('value', array(
					'type' => 'textarea',
					'error' => array('escape' => false),
					'div' => 'input clear',
					'class' => 'input-xxlarge',
					'label' => 'Values'
			));
			$this->Js->get('#AttributeCategory')->event('change', 'formCategoryChanged("#AttributeCategory")');
			?>
			<div class="input clear"></div>
		</div>
	</fieldset>
	<p style="color:red;font-weight:bold;display:none;" id="warning-message">Warning: You are about to share data that is of a classified nature (Attribution / targeting data). Make sure that you are authorised to share this.</p>
		<div class="overlay_spacing">
			<table>
				<tr>
				<td style="vertical-align:top">
					<span id="submitButton" class="btn btn-primary" title="Replace attributes" role="button" tabindex="0" aria-label="Replaceattributes" onClick="submitPopoverForm('<?php echo $event_id;?>', 'replaceAttributes')">Submit</span>
				</td>
				<td style="width:540px;">
					<p style="color:red;font-weight:bold;display:none;text-align:center" id="warning-message">Warning: You are about to share data that is of a classified nature (Attribution / targeting data). Make sure that you are authorised to share this.</p>
				</td>
				<td style="vertical-align:top;">
					<span class="btn btn-inverse" id="cancel_attribute_add" title="Cancel" role="button" tabindex="0" aria-label="Cancel">Cancel</span>
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
//Generate Category / Type filtering array
//
var category_type_mapping = new Array();
<?php
foreach ($categoryDefinitions as $category => $def) {
	echo "category_type_mapping['" . addslashes($category) . "'] = {";
	$first = true;
	foreach ($def['types'] as $type) {
		if ($first) $first = false;
		else echo ', ';
		echo "'" . addslashes($type) . "' : '" . addslashes($type) . "'";
	}
	echo "}; \n";
}
?>

function formCategoryChanged(id) {
	// fill in the types
	var options = $('#AttributeType').prop('options');
	$('option', $('#AttributeType')).remove();
	$.each(category_type_mapping[$('#AttributeCategory').val()], function(val, text) {
		options[options.length] = new Option(text, val);
	});
	// enable the form element
	$('#AttributeType').prop('disabled', false);
}
//
//Generate tooltip information
//
var formInfoValues = new Array();
var fieldsArray = new Array('AttributeCategory', 'AttributeType');
<?php
foreach ($typeDefinitions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
}
foreach ($categoryDefinitions as $category => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($category) . "'] = \"" . addslashes($info) . "\";\n"; // as we output JS code we need to add slashes
}
?>

$(document).ready(function() {
	$("#AttributeType, #AttributeCategory").on('mouseover', function(e) {
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
	$("#AttributeType, #AttributeCategory").on('change', function(e) {
		if (this.id === "AttributeCategory") {
			var select = document.getElementById("AttributeCategory");
			if (select.value === 'Attribution' || select.value === 'Targeting data') {
				$("#warning-message").show();
			} else {
				$("#warning-message").hide();
			}
		}
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
		cancelPopoverForm();
	});
});
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
