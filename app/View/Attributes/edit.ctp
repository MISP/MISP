<div class="attributes form">
<?php echo $this->Form->create('Attribute');?>
	<fieldset>
		<legend><?php echo __('Edit Attribute'); ?></legend>
		<?php
			echo $this->Form->hidden('event_id');
			echo $this->Form->input('category', array(
				'empty' => '(choose one)',
				'label' => 'Category ' . $this->element('formInfo', array('type' => 'category'))
			));
			$typeInputData = array(
				'empty' => '(first choose category)',
				'label' => 'Type ' . $this->element('formInfo', array('type' => 'type')),
			);
			if ($objectAttribute) {
				$typeInputData[] = 'disabled';
			}
			echo $this->Form->input('type', $typeInputData);
		?>
			<div class="input clear"></div>
		<?php
			echo $this->Form->input('distribution', array(
				'options' => array($distributionLevels),
				'label' => 'Distribution ' . $this->element('formInfo', array('type' => 'distribution'))
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
					'label' => 'for Intrusion Detection System',
			));
			if (!$objectAttribute) {
				echo $this->Form->input('batch_import', array(
						'type' => 'checkbox',
				));
			}
		?>
	</fieldset>
		<p style="color:red;font-weight:bold;display:none;<?php if (isset($ajax) && $ajax) echo "text-align:center;";?> " id="warning-message">Warning: You are about to share data that is of a sensitive nature (Attribution / targeting data). Make sure that you are authorised to share this.</p>
<?php
	echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
	echo $this->Form->end();
?>
</div>
<?php
	$event['Event']['id'] = $this->request->data['Attribute']['event_id'];
	$event['Event']['published'] = $published;
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'addAttribute', 'event' => $event));
?>
<script type="text/javascript">
var fieldsArray = new Array('AttributeCategory', 'AttributeType', 'AttributeValue', 'AttributeDistribution', 'AttributeComment', 'AttributeToIds', 'AttributeBatchImport', 'AttributeSharingGroupId');
<?php
	$formInfoTypes = array('distribution' => 'Distribution', 'category' => 'Category', 'type' => 'Type');
	echo 'var formInfoFields = ' . json_encode($formInfoTypes) . PHP_EOL;
	foreach ($formInfoTypes as $formInfoType => $humanisedName) {
		echo 'var ' . $formInfoType . 'FormInfoValues = {' . PHP_EOL;
		foreach ($info[$formInfoType] as $key => $formInfoData) {
			echo '"' . $key . '": "<span class=\"blue bold\">' . h($formInfoData['key']) . '</span>: ' . h($formInfoData['desc']) . '<br />",' . PHP_EOL;
		}
		echo '}' . PHP_EOL;
	}
?>
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

$(document).ready(function() {
	initPopoverContent('Attribute');
	$('#AttributeDistribution').change(function() {
		if ($('#AttributeDistribution').val() == 4) $('#SGContainer').show();
		else $('#SGContainer').hide();
	});

	<?php
		if (!$objectAttribute):
	?>
		$("#AttributeCategory").on('change', function(e) {
			formCategoryChanged('Attribute');
			if ($(this).val() === 'Attribution' || $(this).val() === 'Targeting data') {
				$("#warning-message").show();
			} else {
				$("#warning-message").hide();
			}
			if ($(this).val() === 'Internal reference') {
				$("#AttributeDistribution").val('0');
				$('#SGContainer').hide();
			}
		});
    var start = $("#AttributeType").val();
    formCategoryChanged('Attribute');
    $("#AttributeType").val(start);
	<?php
		endif;
	?>

	$("#AttributeCategory, #AttributeType, #AttributeDistribution").change(function() {
		var start = $("#AttributeType").val();
		initPopoverContent('Attribute');
		$("#AttributeType").val(start);
	});
});
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
