<div class="object_value_field">
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
          'div' => false,
          'value' => empty($element['value']) ? '' : $element['value']
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
            'div' => false,
            'value' => empty($element['value']) ? '' : $element['value']
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
            'div' => false,
            'value' => empty($element['value']) ? '' : $element['value']
          ));
  ?>
        </div>
  <?php
      endif;
    endif;
  ?>
</div>
