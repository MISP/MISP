<div class="attributes <?php if (!isset($ajax) || !$ajax) echo 'form';?>">
<?php
	$url_params = $action == 'add' ? 'add/' . $event_id : 'edit/' . $attribute['Attribute']['id'];
	echo $this->Form->create('Attribute', array('id', 'url' => '/attributes/' . $url_params));
?>
	<fieldset>
		<legend><?php echo $action == 'add' ? __('Add Attribute') : __('Edit Attribute'); ?></legend>
		<div id="formWarning" class="message ajaxMessage"></div>
		<div id="compositeWarning" class="message <?php echo !empty($ajax) ? 'ajaxMessage' : '';?>" style="display:none;">Did you consider adding an object instead of a composite attribute?</div>
		<div class="add_attribute_fields">
			<?php
			echo $this->Form->hidden('event_id');
			echo $this->Form->input('category', array(
				'empty' => __('(choose one)'),
				'label' => __('Category ') . $this->element('formInfo', array('type' => 'category')),
				'class' => 'form-control'
			));
			echo $this->Form->input('type', array(
				'empty' => __('(first choose category)'),
				'label' => __('Type ') . $this->element('formInfo', array('type' => 'type')),
				'class' => 'form-control'
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
				'label' => __('Distribution ') . $this->element('formInfo', array('type' => 'distribution')),
				'selected' => $initialDistribution,
				'class' => 'form-control'
			));
			?>
				<div id="SGContainer" style="display:none;">
			<?php
				if (!empty($sharingGroups)) {
					echo $this->Form->input('sharing_group_id', array(
							'options' => array($sharingGroups),
							'label' => __('Sharing Group'),
							'class' => 'form-control'
					));
				}
			?>
				</div>
			<?php
			echo $this->Form->input('value', array(
					'type' => 'textarea',
					'error' => array('escape' => false),
					'div' => 'input clear',
					'class' => 'form-control input-xxlarge'
			));
			?>
				<div class="input clear"></div>
			<?php
			echo $this->Form->input('comment', array(
					'type' => 'text',
					'label' => __('Contextual Comment'),
					'error' => array('escape' => false),
					'div' => 'input clear',
					'class' => 'form-control input-xxlarge'
			));
			?>
			<div class="input clear"></div>
			<?php
			echo $this->Form->input('to_ids', array(
						'checked' => false,
						'label' => __('for Intrusion Detection System'),
						'class' => 'form-control'
			));
			echo $this->Form->input('batch_import', array(
					'type' => 'checkbox',
					'class' => 'check-control'
			));
		?>
		</div>
	</fieldset>
	<?php if ($ajax): ?>
		<div class="overlay_spacing">
			<table>
				<tr>
				<td style="vertical-align:bottom">
					<span id="submitButton" class="btn btn-primary" title="<?php echo __('Submit'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Submit'); ?>" onClick="submitPopoverForm('<?php echo $action == 'add' ? $event_id : $attribute['Attribute']['id'];?>', '<?php echo $action; ?>')"><?php echo __('Submit'); ?></span>
				</td>
				<td style="width:540px;margin-bottom:0px;">
					<p style="color:red;font-weight:bold;display:none;text-align:center;margin-bottom:0px;" id="warning-message"><?php echo __('Warning: You are about to share data that is of a classified nature. Make sure that you are authorised to share this.'); ?></p>
				</td>
				<td style="vertical-align:bottom;">
					<span class="btn btn-dark" title="<?php echo __('Cancel'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel'); ?>" id="cancel_attribute_add"><?php echo __('Cancel'); ?></span>
				</td>
				</tr>
			</table>
		</div>
	<?php
		else:
	?>
		<p style="color:red;font-weight:bold;display:none;" id="warning-message"><?php echo __('Warning: You are about to share data that is of a classified nature. Make sure that you are authorised to share this.'); ?></p>
	<?php
			echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
		endif;
		echo $this->Form->end();
	?>
</div>
<?php
	if (!$ajax) {
		$event['Event']['id'] = $event_id;
		$event['Event']['published'] = $published;
		echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'addAttribute', 'event' => $event));
	}
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

var composite_types = <?php echo json_encode($compositeTypes); ?>;

$(document).ready(function() {
	initPopoverContent('Attribute');
	$('#AttributeDistribution').change(function() {
		if ($('#AttributeDistribution').val() == 4) $('#SGContainer').show();
		else $('#SGContainer').hide();
	});

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

	$("#AttributeCategory, #AttributeType, #AttributeDistribution").change(function() {
		var start = $("#AttributeType").val();
		initPopoverContent('Attribute');
		$("#AttributeType").val(start);
		if ($.inArray(start, composite_types) > -1) {
			$('#compositeWarning').show();
		} else {
			$('#compositeWarning').hide();
		}
	});
	<?php if ($ajax): ?>
		$('#cancel_attribute_add').click(function() {
			cancelPopoverForm();
		});

	<?php endif; ?>
});
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
