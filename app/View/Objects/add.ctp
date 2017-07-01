<div class="<?php if (!isset($ajax) || !$ajax) echo 'form';?>">
<div>
  <?php
  	echo $this->Form->create('Object', array('id', 'url' => '/objects/add/' . $event['Event']['id'] . '/' . $template['ObjectTemplate']['id']));
    echo $this->Form->input('data', array(
      'style' => 'display:none;',
      'label' => false
    ));
    echo $this->Form->end();
  ?>
</div>
<h3><?php echo 'Add ' . Inflector::humanize(h($template['ObjectTemplate']['name'])) . ' Object'; ?></h3>
<div class="row-fluid">
  <dl class="span8">
    <dt>Object Template</dt>
    <dd>
      <?php echo Inflector::humanize(h($template['ObjectTemplate']['name'])); ?>&nbsp;
    </dd>
    <dt>Description</dt>
    <dd>
      <?php echo h($template['ObjectTemplate']['description']); ?>&nbsp;
    </dd>
    <?php
      if (!empty($template['ObjectTemplate']['requirements']['required']) || !empty($template['ObjectTemplate']['requirements']['requiredOneOf'])):
    ?>
        <dt>Requirements</dt>
        <dd>
          <?php
            if (!empty($template['ObjectTemplate']['requirements']['required'])) {
              echo '<span class="bold">Required</span>: ' . h(implode(', ', $template['ObjectTemplate']['requirements']['required'])) . '<br />';
            }
            if (!empty($template['ObjectTemplate']['requirements']['requiredOneOf'])) {
              echo '<span class="bold">Required one of</span>: ' . h(implode(', ', $template['ObjectTemplate']['requirements']['requiredOneOf']));
            }
          ?>
        </dd>
    <?php
      endif;
    ?>
    <dt>Meta category</dt>
    <dd>
      <?php echo Inflector::humanize(h($template['ObjectTemplate']['meta-category'])); ?>&nbsp;
    </dd>
  </dl>
  <table class="table table-striped table-condensed">
    <tr>
      <th>Name</th>
      <th>Type</th>
      <th>Category</th>
      <th>Value</th>
      <th>Description</th>
      <th>To IDS</th>
      <th>Distribution</th>
    </tr>
  <?php
    foreach ($template['ObjectTemplateElement'] as $k => $element):
  ?>
    <tr>
      <td class="shortish bold">
        <?php echo Inflector::humanize(h($element['in-object-name'])); ?>
      </td>
      <td class="short">
        <?php echo h($element['type']); ?>
      </td>
      <td class="short">
        <select>
          <?php
            foreach ($element['categories'] as $category):
          ?>
            <option id="category_select_<?php echo h($k); ?>" value="<?php echo h($category); ?>" <?php echo $category == $element['default_category'] ? 'selected' : ''; ?>>
              <?php echo h($category);?>
            </option>
          <?php
            endforeach;
          ?>
        </select>
      </td>
      <td>
        <?php
          if (empty($element['values_list'])):
        ?>
            <textarea id="value_select_<?php echo h($k); ?>" class="input" style="height:20px;width:400px;" <?php echo 'list="value_select_list_' . $k . '"'; ?>></textarea>
        <?php
            if (!empty($elements['sane_default'])):
        ?>
              <datalist id="exampleList">
                  <option value="A">
                  <option value="B">
              </datalist>
        <?php
            endif;
          else:
        ?>

        <?php
          endif;
        ?>
      </td>
    </tr>
  <?php
    endforeach;
  ?>
</table>
</div>
	<?php if ($ajax): ?>
		<div class="overlay_spacing">
			<table>
				<tr>
				<td style="vertical-align:bottom">
					<span id="submitButton" class="btn btn-primary" title="Submit" role="button" tabindex="0" aria-label="Submit" onClick="submitPopoverForm('<?php echo $event_id;?>', 'add')">Submit</span>
				</td>
				<td style="width:540px;margin-bottom:0px;">
					<p style="color:red;font-weight:bold;display:none;text-align:center;margin-bottom:0px;" id="warning-message">Warning: You are about to share data that is of a classified nature. Make sure that you are authorised to share this.</p>
				</td>
				<td style="vertical-align:bottom;">
					<span class="btn btn-inverse" title="Cancel" role="button" tabindex="0" aria-label="Cancel" id="cancel_attribute_add">Cancel</span>
				</td>
				</tr>
			</table>
		</div>
	<?php
		else:
	?>
		<p style="color:red;font-weight:bold;display:none;" id="warning-message">Warning: You are about to share data that is of a classified nature. Make sure that you are authorised to share this.</p>
	<?php
			echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
		endif;
		echo $this->Form->end();
	?>
</div>
<?php
	if (!$ajax) {
		echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'addObject', 'event' => $event));
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
		initPopoverContent('Attribute');
	});
	<?php if ($ajax): ?>
		$('#cancel_attribute_add').click(function() {
			cancelPopoverForm();
		});

	<?php endif; ?>
});
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
