<div class="template_element_add_attribute">
<?php
	echo $this->Form->create('TemplateElementAttribute', array('id', 'url' => '/templateElements/add/attribute/' . $id));
?>
	<legend><?php echo __('Add Attribute Element To Template'); ?></legend>
	<fieldset>
		<div id="formWarning" class="message ajaxMessage"></div>
		<div class="add_attribute_fields">
			<?php
				echo $this->Form->input('name', array(
						'type' => 'text',
						'error' => array('escape' => false),
						'div' => 'input clear',
						'class' => 'input-xxlarge'
				));

				echo $this->Form->input('description', array(
						'type' => 'textarea',
						'error' => array('escape' => false),
						'div' => 'input clear',
								'class' => 'input-xxlarge'
				));
			?>
				<div class="input clear"></div>
			<?php
				echo $this->Form->input('category', array(
						'options' => array($categories),
						'label' => 'Category',
						'empty' => 'Select Category'
				));
			?>
			<div id='typeToggle'>
				<?php
					echo $this->Form->input('type', array(
						'options' => array(),
						'label' => 'Type',
						'empty' => 'Select Type'
					));

				?>
			</div>
			<div class="input clear"></div>
			<div id='complexToggle' style="display:none;" title="Some categories can use complex types. A complex type can define attributes that can be described by various different types, the system will parse the user's entry and determine the most suitable type for the found attributes. The list of valid types for the chosen complex type is shown below.">
				<?php
					echo $this->Form->input('complex', array(
							'checked' => false,
							'label' => 'Use complex types',
					));

				?>
			</div>
			<div class="input clear"></div>
			<div id="typeJSON" style="display:none"></div>
			<div class="input clear" style="width:100%;display:none" id="outerTypes">
				Types allowed based on the above setting:
				<div class="templateTypeContainerInner" id="innerTypes">&nbsp;</div>
			</div>
			<div class="input clear"></div>
			<div title="When checked, attributes created using this element will automatically be marked for IDSes.">
				<?php
					echo $this->Form->input('to_ids', array(
							'checked' => false,
							'label' => 'Automatically mark for IDS',
					));
				?>
			</div>
			<div class="input clear"></div>
			<div title="This setting will make this element mandatory.">
				<?php
					echo $this->Form->input('mandatory', array(
							'checked' => false,
							'label' => 'Mandatory element',
					));
				?>
			<div>
			<div class="input clear"></div>
			<div title="If this checkbox is checked, then the resulting field in the form will allow several values to be entered (separated by a linebreak).">
				<?php
					echo $this->Form->input('batch', array(
							'checked' => false,
							'label' => 'Batch import element',
					));
				?>
			</div>
		</div>
	</fieldset>
	<div class="overlay_spacing">
		<table>
			<tr>
			<td style="vertical-align:top">
				<span id="submitButton" role="span" tabindex="0" aria-label="Add attribute element" title="Add attribute element" class="btn btn-primary" onClick="return submitPopoverForm('<?php echo $id;?>', 'addAttributeElement')">Submit</span>
			</td>
			<td style="width:540px;">
				<p style="color:red;font-weight:bold;display:none;text-align:center" id="warning-message">Warning: You are about to share data that is of a classified nature (Attribution / targeting data). Make sure that you are authorised to share this.</p>
			</td>
			<td style="vertical-align:top;">
				<span role="span" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" id="cancel_attribute_add" onClick="cancelPopoverForm();">Cancel</span>
			</td>
			</tr>
		</table>
	</div>
	<?php
		echo $this->Form->end();
	?>
</div>
<script type="text/javascript">
	var categoryTypes = new Array();
	var typeGroupCategoryMapping = <?php echo json_encode($typeGroupCategoryMapping); ?>;
	var complexTypes = <?php echo json_encode($validTypeGroups); ?>;
	var currentTypes = new Array();
	var fieldsArray = new Array('TemplateElementAttributeName', 'TemplateElementAttributeDescription', 'TemplateElementAttributeCategory', 'TemplateElementAttributeToIds', 'TemplateElementAttributeMandatory', 'TemplateElementAttributeBatch', 'TemplateElementAttributeType', 'TemplateElementAttributeComplex');

	$(document).ready(function() {
		<?php
			foreach ($categoryDefinitions as $k => $cat) {
				echo 'categoryTypes[\'' . $k . '\'] = [';
					foreach ($cat['types'] as $k => $type) {
						if ($k != 0) echo ', ';
						echo '"' . $type . '"';
					}
				echo '];';
			}

			foreach ($typeGroupCategoryMapping as $k => $mapping) {
				echo 'typeGroupCategoryMapping["' . $k . '"] = [';
				foreach ($mapping as $l => $map) {
					if ($l != 0) echo ', ';
					echo '"' . $map . '"';
				}
				echo '];';
			}
		?>
	});

	$("#TemplateElementAttributeCategory").change(function() {
		var category = $(this).val();
		templateElementAttributeCategoryChange(category);
	});

	$("#TemplateElementAttributeComplex").change(function() {
		populateTemplateTypeDropdown();
		templateUpdateAvailableTypes();
	});

	$("#TemplateElementAttributeType").change(function() {
		templateElementAttributeTypeChange();
	});

</script>
