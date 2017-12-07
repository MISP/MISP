<div class="<?php if (!isset($ajax) || !$ajax) echo 'form';?>">
<?php
	$url = ($action == 'add') ? '/objects/revise_object/add/' . $event['Event']['id'] . '/' . $template['ObjectTemplate']['id'] : '/objects/revise_object/edit/' . $event['Event']['id'] . '/' . $template['ObjectTemplate']['id'] . '/' . $object['Object']['id'];
	echo $this->Form->create('Object', array('id', 'url' => $url, 'enctype' => 'multipart/form-data'));
?>
<h3><?php echo ucfirst($action) . ' ' . Inflector::humanize(h($template['ObjectTemplate']['name'])) . ' Object'; ?></h3>
<div class="row-fluid" style="margin-bottom:10px;">
  <dl class="span8">
    <dt>Object Template</dt>
    <dd>
      <?php
        echo Inflector::humanize(h($template['ObjectTemplate']['name'])) . ' v' . h($template['ObjectTemplate']['version']);
      ?>
      &nbsp;
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
    <dt>Distribution</dt>
    <dd>
      <?php
          echo $this->Form->input('Object.distribution', array(
            'class' => 'Object_distribution_select',
            'options' => $distributionData['levels'],
            'default' => $distributionData['initial'],
            'label' => false,
            'style' => 'margin-bottom:5px;',
            'div' => false
          ));
        echo $this->Form->input('Object.sharing_group_id', array(
          'class' => 'Object_sharing_group_id_select',
          'options' => $distributionData['sgs'],
          'label' => false,
          'div' => false,
          'style' => 'display:none;margin-bottom:5px;'
        ));
      ?>
    </dd>
    <dt>Comment</dt>
    <dd>
      <?php
        echo $this->Form->input('Object.comment', array(
          'type' => 'textarea',
          'style' => 'height:20px;width:400px;',
          'required' => false,
          'allowEmpty' => true,
          'label' => false,
          'div' => false,
					'value' => empty($template['Object']['comment']) ? '' : $template['Object']['comment']
        ));
      ?>
    </dd>
  </dl>
</div>
<?php
	if (!empty($template['warnings'])):
	?>
		<span class="red bold">Warning, issues found with the template:</span>
		<div class="red">
	<?php
			foreach ($template['warnings'] as $warning) {
				echo h($warning) . '<br />';
			}
	?>
		</div>
	<?php
	endif;
?>
<table class="table table-striped table-condensed">
  <tr>
    <th>Save</th>
    <th>Name :: type</th>
		<th>Description</th>
    <th>Category</th>
    <th>Value</th>
    <th>IDS</th>
		<th>Disable Correlation</th>
    <th>Distribution</th>
    <th>Comment</th>
  </tr>
<?php
  $row_list = array();
  foreach ($template['ObjectTemplateElement'] as $k => $element):
    $row_list[] = $k;
		echo $this->element(
	    'Objects/object_add_attributes',
	    array(
	      'element' => $element,
	      'k' => $k,
				'action' => $action,
				'enabledRows' => $enabledRows
	    )
	  );
		if ($element['multiple']):
			$lastOfType = true;
			$lookAheadArray = array_slice($template['ObjectTemplateElement'], $k, count($template['ObjectTemplateElement']), true);
			if (count($lookAheadArray) > 1) {
				foreach ($lookAheadArray as $k2 => $temp) {
					if ($k2 == $k) continue;
					if ($temp['object_relation'] == $element['object_relation']) {
						$lastOfType = false;
					}
				}
			}
			if ($lastOfType):
	?>
			<tr id="row_<?php echo h($element['object_relation']); ?>_expand">
				<td class="down-expand-button add_object_attribute_row" colspan="9" data-template-id="<?php echo h($template['ObjectTemplate']['id']);?>" data-target-row="<?php echo h($k); ?>" data-object-relation="<?php echo h($element['object_relation']); ?>">
					<span class="fa fa-angle-double-down" ></span>
				</td>
			</tr>
	<?php
			endif;
		endif;
	?>
<?php
  endforeach;
?>
</table>
<div id="last-row" class="hidden" data-last-row="<?php echo h($k); ?>"></div>
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
  var rows = <?php echo json_encode($row_list, true); ?>;
  $(document).ready(function() {
    enableDisableObjectRows(rows);
		$(".Attribute_value_select").each(function() {
      checkAndEnable($(this).parent().find('.Attribute_value'), $(this).val() == 'Enter value manually');
    });
    $(".Attribute_distribution_select").change(function() {
      checkAndEnable($(this).parent().find('.Attribute_sharing_group_id_select'), $(this).val() == 4);
    });

    $(".Object_distribution_select").change(function() {
      checkAndEnable($(this).parent().find('.Object_sharing_group_id_select'), $(this).val() == 4);
    });
    $(".Attribute_value_select").change(function() {
      checkAndEnable($(this).parent().find('.Attribute_value'), $(this).val() == 'Enter value manually');
    });
		$('.add_attribute_row').click(function() {
			var selector = $(this).data('target');
			var count = $(this).parent().children(selector).length;
			$(this).parent().children(selector).first().clone().appendTo($(this).parent()).insertBefore($('.add_unlocked_field'));
		});
  });
</script>
