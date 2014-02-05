<div class="shadow_attributes form">
<?php echo $this->Form->create('ShadowAttribute', array('enctype' => 'multipart/form-data','onSubmit' => 'document.getElementById("ShadowAttributeMalware").removeAttribute("disabled");'));?>
	<fieldset>
			<legend><?php echo __('Add Attachment'); ?></legend>
	<?php
		echo $this->Form->hidden('event_id');
		echo $this->Form->input('category');
		?>
			<div class="input clear">
		<?php
		echo $this->Form->file('value', array(
			'error' => array('escape' => false),
		));
		?>
			</div>
			<div class="input clear"><br /></div>
			<div class="input clear"></div>
		<?php
		echo $this->Form->input('malware', array(
				'type' => 'checkbox',
				'checked' => false,
		));
		// link an onchange event to the form elements
		$this->Js->get('#ShadowAttributeType')->event('change', 'showFormInfo("#ShadowAttributeType")');
		$this->Js->get('#ShadowAttributeCategory')->event('change', 'showFormInfo("#ShadowAttributeCategory")');
	?>
	</fieldset>
<?php
	echo $this->Form->button('Propose', array('class' => 'btn btn-primary'));
	echo $this->Form->end();
?>
</div>
<?php 
	$event['Event']['id'] = $this->request->data['ShadowAttribute']['event_id'];
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'proposeAttachment', 'event' => $event));
?>
	
<script type="text/javascript">

$(document).ready(function() {

	$("#ShadowAttributeCategory, #ShadowAttribute").on('mouseover', function(e) {
	    var $e = $(e.target);
	    if ($e.is('option')) {
	        $('#'+e.currentTarget.id).popover('destroy');
	        $('#'+e.currentTarget.id).popover({
	            trigger: 'focus',
	            placement: 'right',
	            content: formInfoValues[$e.val()],
	        }).popover('show');
	    }
	});

	// workaround for browsers like IE and Chrome that do now have an onmouseover on the 'options' of a select.
	// disadvangate is that user needs to click on the item to see the tooltip.
	// no solutions exist, except to generate the select completely using html.
	$("#ShadowAttributeCategory, #ShadowAttribute").on('change', function(e) {
	    var $e = $(e.target);
      $('#'+e.currentTarget.id).popover('destroy');
      $('#'+e.currentTarget.id).popover({
          trigger: 'focus',
          placement: 'right',
          content: formInfoValues[$e.val()],
      }).popover('show');
	});

});

//
//Generate tooltip information
//
var formInfoValues = new Array();
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
function showFormInfo(id) {
	idDiv = id+'Div';
	// LATER use nice animations
	//$(idDiv).hide('fast');
	// change the content
	var value = $(id).val();    // get the selected value
	$(idDiv).html(formInfoValues[value]);    // search in a lookup table

	// show it again
	$(idDiv).fadeIn('slow');
}

//hide the formInfo things
$('#ShadowAttributeTypeDiv').hide();
$('#ShadowAttributeCategoryDiv').hide();
$('#ShadowAttributeType').prop('disabled', true);


</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
	
