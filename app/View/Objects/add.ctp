<div class="<?php if (!isset($ajax) || !$ajax) echo 'form';?>">
<?php
	echo $this->Form->create('Object', array('id', 'url' => '/objects/add/' . $event['Event']['id'] . '/' . $template['ObjectTemplate']['id'], 'enctype' => 'multipart/form-data'));
?>
<h3><?php echo 'Add ' . Inflector::humanize(h($template['ObjectTemplate']['name'])) . ' Object'; ?></h3>
<div class="row-fluid" style="margin-bottom:10px;">
  <dl class="span8">
    <dt>Object Template</dt>
    <dd>
      <?php
        echo Inflector::humanize(h($template['ObjectTemplate']['name']));
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
            'style' => 'margin-bottom:0px;',
            'div' => false
          ));
        echo $this->Form->input('Object.sharing_group_id', array(
          'class' => 'Object_sharing_group_id_select',
          'options' => $distributionData['sgs'],
          'label' => false,
          'div' => false,
          'style' => 'display:none;margin-bottom:0px;'
        ));
      ?>
    </dd>
  </dl>
</div>
<table class="table table-striped table-condensed">
  <tr>
    <th>Save</th>
    <th>Name :: type</th>
    <th>Category</th>
    <th>Value</th>
    <th>IDS</th>
    <th>Distribution</th>
    <th>Comment</th>
  </tr>
<?php
  $row_list = array();
  foreach ($template['ObjectTemplateElement'] as $k => $element):
    $row_list[] = $k;
?>
  <tr>
    <td>
      <?php
        echo $this->Form->input('Attribute.' . $k . '.save', array(
          'type' => 'checkbox',
          'checked' => in_array($k, $enabledRows),
          'label' => false,
          'div' => false
        ));
      ?>
    </td>
    <td class="shortish" title="<?php echo h($element['description']); ?>">
      <?php
        echo $this->Form->input('Attribute.' . $k . '.object_relation', array(
          'type' => 'hidden',
          'value' => $element['in-object-name'],
          'label' => false,
          'div' => false
        ));
        echo $this->Form->input('Attribute.' . $k . '.type', array(
          'type' => 'hidden',
          'value' => $element['type'],
          'label' => false,
          'div' => false
        ));
        echo '<span class="bold">' . Inflector::humanize(h($element['in-object-name'])) . '</span>';
        if (!empty($template['ObjectTemplate']['requirements']['required']) && in_array($element['in-object-name'], $template['ObjectTemplate']['requirements']['required'])) {
          echo '<span class="bold red">' . '(*)' . '</span>';
        }
        echo ' :: ' . h($element['type']) . '';
      ?>
    </td>
    <td class="short">
      <?php
        echo $this->Form->input('Attribute.' . $k . '.category', array(
          'options' => array_combine($element['categories'], $element['categories']),
          'default' => $element['default_category'],
          'style' => 'margin-bottom:0px;',
          'label' => false,
          'div' => false
        ));
      ?>
    </td>
    <td>
      <?php
        if ($element['type'] == 'malware-sample' || $element['type'] == 'attachment'):
          echo $this->Form->file('Attribute.' . $k . '.Attachment', array(
            'class' => 'Attribute_attachment'
          ));
        else:
          if (empty($element['values_list']) && empty($element['sane_default'])):
            echo $this->Form->input('Attribute.' . $k . '.value', array(
              'type' => 'textarea',
              'required' => false,
              'allowEmpty' => true,
              'style' => 'height:20px;width:400px;',
              'label' => false,
              'div' => false
            ));
          else:
            if (empty($element['values_list'])) {
              $list = $element['sane_default'];
              $list[] = 'Enter value manually';
            } else {
              $list = $element['values_list'];
            }
            $list = array_combine($list, $list);
      ?>
            <div class="value_select_with_manual_entry">
      <?php
              echo $this->Form->input('Attribute.' . $k . '.value_select', array(
                'class' => 'Attribute_value_select',
                'style' => 'width:414px;margin-bottom:0px;',
                'options' => array_combine($list, $list),
                'label' => false,
                'div' => false
              ));
      ?>
        <br />
      <?php
              echo $this->Form->input('Attribute.' . $k . '.value', array(
                'class' => 'Attribute_value',
                'type' => 'textarea',
                'required' => false,
                'allowEmpty' => true,
                'style' => 'height:20px;width:400px;display:none;',
                'label' => false,
                'div' => false
              ));
      ?>
            </div>
      <?php
          endif;
        endif;
      ?>
    </td>
    <td>
      <?php
        echo $this->Form->input('Attribute.' . $k . '.to_ids', array(
          'type' => 'checkbox',
          'checked' => $element['to_ids'],
          'label' => false,
          'div' => false
        ));
      ?>
    </td>
    <td class="short">
      <?php
          echo $this->Form->input('Attribute.' . $k . '.distribution', array(
            'class' => 'Attribute_distribution_select',
            'options' => $distributionData['levels'],
            'default' => $distributionData['initial'],
            'style' => 'margin-bottom:0px;',
            'label' => false,
            'div' => false
          ));
      ?>
      <br />
      <?php
        echo $this->Form->input('Attribute.' . $k . '.sharing_group_id', array(
          'class' => 'Attribute_sharing_group_id_select',
          'options' => $distributionData['sgs'],
          'label' => false,
          'div' => false,
          'style' => 'display:none;margin-bottom:0px;',
        ));
      ?>
    </td>
    <td>
      <?php
        echo $this->Form->input('Attribute.' . $k . '.comment', array(
          'type' => 'textarea',
          'style' => 'height:20px;width:400px;',
          'required' => false,
          'allowEmpty' => true,
          'label' => false,
          'div' => false
        ));
      ?>
    </td>
  </tr>
<?php
  endforeach;
?>
</table>
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

    $(".Attribute_distribution_select").change(function() {
      checkAndEnable($(this).parent().find('.Attribute_sharing_group_id_select'), $(this).val() == 4);
    });

    $(".Object_distribution_select").change(function() {
      checkAndEnable($(this).parent().find('.Object_sharing_group_id_select'), $(this).val() == 4);
    });

    $(".Attribute_value_select").change(function() {
      checkAndEnable($(this).parent().find('.Attribute_value'), $(this).val() == 'Enter value manually');
    });
  });
</script>
