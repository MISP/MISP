<div class="attributes <?php if (!isset($ajax) || !$ajax) echo 'form';?>">
<?php
	echo $this->Form->create('Attribute', array('id'));
?>
	<fieldset>
		<legend><?php echo __('Add Attribute'); ?></legend>
		<div id="formWarning" class="message ajaxMessage"></div>
		<div class="add_attribute_fields">
			<?php
			echo $this->Form->hidden('event_id');
			echo $this->Form->input('category', array(
					'empty' => '(choose one)'
					));
			echo $this->Form->input('type', array(
					'empty' => '(first choose category)'
					));

			$initialDistribution = 5;
			if (Configure::read('MISP.default_attribute_distribution') != null) {
				if (Configure::read('MISP.default_attribute_distribution') === 'event') {
					$initialDistribution = 5;
				} else {
					$initialDistribution = Configure::read('MISP.default_attribute_distribution');
				}
			}

			?>
				<div class="input clear"></div>
			<?php

			echo $this->Form->input('distribution', array(
				'options' => array($distributionLevels),
				'label' => 'Distribution',
				'selected' => $initialDistribution,
			));
			?>
				<div id="SGContainer" style="display:none;">
			<?php
				if (!empty($sharingGroups)) {
					echo $this->Form->input('sharing_group_id', array(
							'options' => array($sharingGroups),
							'label' => 'Sharing Group',
					));
				}
			?>
				</div>
			<?php
			echo $this->Form->input('value', array(
					'type' => 'textarea',
					'error' => array('escape' => false),
					'div' => 'input clear',
					'class' => 'input-xxlarge'
			));
			?>
				<div class="input clear"></div>
			<?php
			echo $this->Form->input('comment', array(
					'type' => 'text',
					'label' => 'Contextual Comment',
					'error' => array('escape' => false),
					'div' => 'input clear',
					'class' => 'input-xxlarge'
			));
			?>
			<div class="input clear"></div>
			<?php
			echo $this->Form->input('to_ids', array(
						'checked' => false,
						'data-content' => isset($attrDescriptions['signature']['formdesc']) ? $attrDescriptions['signature']['formdesc'] : $attrDescriptions['signature']['desc'],
						'label' => 'for Intrusion Detection System',
			));
			echo $this->Form->input('batch_import', array(
					'type' => 'checkbox',
					'data-content' => 'Create multiple attributes one per line',
			));
			// link an onchange event to the form elements
			$this->Js->get('#AttributeCategory')->event('change', 'formCategoryChanged("#AttributeCategory")');
		?>
		</div>
	</fieldset>
	<p style="color:red;font-weight:bold;display:none;<?php if (isset($ajax) && $ajax) echo "text-align:center;"?>" id="warning-message">Warning: You are about to share data that is of a sensitive nature (Attribution / targeting data). Make sure that you are authorised to share this.</p>
	<?php if ($ajax): ?>
		<div class="overlay_spacing">
			<table>
				<tr>
				<td style="vertical-align:top">
					<span id="submitButton" class="btn btn-primary" onClick="submitPopoverForm('<?php echo $event_id;?>', 'add')">Submit</span>
				</td>
				<td style="width:540px;">
					<p style="color:red;font-weight:bold;display:none;text-align:center" id="warning-message">Warning: You are about to share data that is of a classified nature (Attribution / targeting data). Make sure that you are authorised to share this.</p>
				</td>
				<td style="vertical-align:top;">
					<span class="btn btn-inverse" id="cancel_attribute_add">Cancel</span>
				</td>
				</tr>
			</table>
		</div>
	<?php
		else:
			echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
		endif;
		echo $this->Form->end();
	?>
	<div id="confirmation_box" class="confirmation_box"></div>
</div>
<?php
	if (!$ajax) {
		$event['Event']['id'] = $this->request->data['Attribute']['event_id'];
		$event['Event']['published'] = $published;
		echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'addAttribute', 'event' => $event));
	}
?>

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
// Generate tooltip information
//
var formInfoValues = new Array();
var fieldsArray = new Array('AttributeCategory', 'AttributeType', 'AttributeDistribution', 'AttributeValue', 'AttributeComment', 'AttributeToIds', 'AttributeBatchImport');
<?php
foreach ($typeDefinitions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
}
foreach ($categoryDefinitions as $category => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($category) . "'] = \"" . addslashes($info) . "\";\n"; // as we output JS code we need to add slashes
}
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

	$("#AttributeType, #AttributeCategory, #Attribute, #AttributeDistribution").on('mouseover', function(e) {
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
	$("#AttributeType, #AttributeCategory, #Attribute, #AttributeDistribution").on('change', function(e) {
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

	<?php if ($ajax): ?>
		$('#cancel_attribute_add').click(function() {
			cancelPopoverForm();
		});

	<?php endif; ?>
});
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
