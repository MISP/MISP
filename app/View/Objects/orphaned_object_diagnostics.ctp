<div class="index">
    <?php
    echo '<h2>' . __('Object reconstruction') . '</h2>';
    echo '<p>';
    echo __('Due to a bug prior to version 2.4.89, a condition could cause objects to be overwritten on a pull, leading to orphaned object attributes. This script reconstructs the missing objects if any exist.');
    echo '<span class="bold">' . __(' Please create a backup of your mysql database before executing the script.') . '</span>';
    echo '</p>';
    if (empty($unmapped) && empty($captured)) {
      echo '<h3 class="red">' .  __('No unmapped data found, everything is working as expected.') . '</h3>';
    }
    $object_fields = array('event_id', 'uuid', 'name', 'meta-category', 'distribution', 'sharing_group_id');
    $attribute_fields = array('id', 'object_relation', 'type', 'category', 'value');
    $reference_fields = array('event_id', 'object_uuid', 'referenced_uuid', 'relationship_type');
    $current_event = false;
    if (!empty($unmapped)) {
      echo '<h3 class="red">' .  __('Unmapped Attributes') . '</h3>';
      echo '<p>' . __('Keep in mind that some of the unmapped attributes can get reconstructed on a second pass of this script.') . '</p>';
      foreach ($unmapped as $attribute) {
        foreach ($attribute_fields as $field) {
          if ($current_event != $attribute['event_id']) {
            echo '<a href="' . $baseurl . '/events/view/' . h($attribute['event_id']) . '" class="red">' . __('Event') . ' ' . h($attribute['event_id']) . '</a><br />&nbsp;&nbsp;';
            $current_event = $attribute['event_id'];
          }
          echo '<span class="bold">' . $field . ':</span> ' . h($attribute[$field]) . '&nbsp;';
        }
        echo '<br />&nbsp;&nbsp;';
      }
    }
    if (!empty($captured)) {
      echo '<h3 class="blue">' . __('Reconstructable objects') . '</h3>';
      echo $this->Form->create();
      $submit_options = array(
        'label' => 'Reconstruct objects',
        'class' => 'btn btn-primary'
      );
      echo $this->Form->end($submit_options);
      foreach ($captured as $object) {
        echo '<span class="blue bold">' . __('Object') . '</span><br />&nbsp;&nbsp;';
        foreach ($object_fields as $ofield) {
          if (isset($object['Object'][$ofield])) {
            echo '<span class="bold">' . $ofield . ':</span> ' . h($object['Object'][$ofield]) . '<br />&nbsp;&nbsp;';
          }
        }
        echo '<span class="bold">' . __('Attributes') . '</span><br />';
        foreach ($object['Attribute'] as $attribute) {
          echo '&nbsp;&nbsp;&nbsp;&nbsp;';
          foreach ($attribute_fields as $field) {
            echo '<span class="bold">' . $field . ':</span> ' . h($attribute[$field]) . '&nbsp;';
          }
          echo '<br />';
        }
        if (!empty($object['ObjectReference'])) {
          echo '<span class="bold">' . __('References') . '</span><br />';
          foreach ($object['ObjectReference'] as $object_ref) {
            echo '&nbsp;&nbsp;&nbsp;&nbsp;';
            foreach ($reference_fields as $field) {
              echo '<span class="bold">' . $field . ':</span> ' . h($object_ref[$field]) . '&nbsp;';
            }
          }
        }
        if (!empty($object['ObjectReferenceReverse'])) {
          echo '<span class="bold">' . __('Referenced by') . '</span><br />';
          foreach ($object['ObjectReferenceReverse'] as $object_ref) {
            echo '&nbsp;&nbsp;&nbsp;&nbsp;';
            foreach ($reference_fields as $field) {
              echo '<span class="bold">' . $field . ':</span> ' . h($object_ref[$field]) . '&nbsp;';
            }
          }
        }
        echo '<br /><br />';
      }
    }
    ?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>
