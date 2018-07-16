<tr id="row_<?php echo h($k); ?>" class="attribute_row">
  <td>
    <?php
      if (empty($enabledRows)) $enabledRows = array();
      if (empty($action)) $action = 'add';
      echo $this->Form->input('Attribute.' . $k . '.save', array(
        'type' => 'checkbox',
        'checked' => in_array($k, $enabledRows),
        'label' => false,
        'div' => false
      ));
    ?>
  </td>
  <td class="short" title="<?php echo h($element['description']); ?>">
    <?php
      $formSettings = array(
        'type' => 'hidden',
        'value' => $element['object_relation'],
        'label' => false,
        'div' => false
      );
      echo $this->Form->input('Attribute.' . $k . '.object_relation', $formSettings);
      if ($action == 'edit') {
        echo $this->Form->input('Attribute.' . $k . '.uuid', array(
          'type' => 'hidden',
          'label' => false,
          'div' => false,
          'value' => !empty($element['uuid']) ? $element['uuid'] : ''
        ));
      }
      $formSettings = array(
        'type' => 'hidden',
        'value' => $element['type'],
        'label' => false,
        'div' => false
      );
      echo $this->Form->input('Attribute.' . $k . '.type', $formSettings);
      echo '<span class="bold">' . Inflector::humanize(h($element['object_relation'])) . '</span>';
      if (!empty($template['ObjectTemplate']['requirements']['required']) && in_array($element['object_relation'], $template['ObjectTemplate']['requirements']['required'])) {
        echo '<span class="bold red">' . '(*)' . '</span>';
      }
      echo ' :: ' . h($element['type']) . '';
    ?>
  </td>
  <td>
    <?php echo h($element['description']); ?>
  </td>
  <td class="short">
    <?php
      $formSettings = array(
        'options' => array_combine($element['categories'], $element['categories']),
        'default' => $element['default_category'],
        'style' => 'margin-bottom:0px;',
        'label' => false,
        'div' => false
      );
      echo $this->Form->input('Attribute.' . $k . '.category', $formSettings);
    ?>
  </td>
  <td class="short">
    <?php
      echo $this->element(
        'Objects/object_value_field',
        array(
          'element' => $element,
          'k' => $k,
          'action' => $action
        )
      );
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
  <td>
    <?php
      echo $this->Form->input('Attribute.' . $k . '.disable_correlation', array(
        'type' => 'checkbox',
        'checked' => $element['disable_correlation'],
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
          'default' => !empty($element['distribution']) ? $element['distribution'] : $distributionData['initial'],
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
        'default' => !empty($element['sharing_group_id']) ? $element['sharing_group_id'] : false,
        'label' => false,
        'div' => false,
        'style' => 'display:none;margin-bottom:0px;',
      ));
    ?>
  </td>
  <td class="short">
    <?php
      echo $this->Form->input('Attribute.' . $k . '.comment', array(
        'type' => 'textarea',
        'style' => 'height:20px;width:400px;',
        'required' => false,
        'allowEmpty' => true,
        'label' => false,
        'div' => false,
        'value' => empty($element['comment']) ? '' : $element['comment']
      ));
    ?>
  </td>
</tr>
