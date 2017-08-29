<div class="form">
  <h3>Object pre-save review</h3>
  <p>Make sure that the below Object reflects your expectation before submiting it.</p>
  <?php
    $url = ($action == 'add') ? '/objects/add/' . $event['Event']['id'] . '/' . $template['ObjectTemplate']['id'] : '/objects/edit/' . $object_id;
    echo $this->Form->create('Object', array('id', 'url' => $url));
    $formSettings = array(
      'type' => 'hidden',
      'value' => json_encode($data, true),
      'label' => false,
      'div' => false
    );
    echo $this->Form->input('data', $formSettings);
  ?>
    <div style="margin-bottom:20px;">
      <span class="bold">Name</span>: <?php echo h($template['ObjectTemplate']['name']); ?><br />
      <span class="bold">Meta-category</span>: <?php echo h($template['ObjectTemplate']['meta-category']); ?><br />
      <span class="bold">Distribution</span>:
      <?php
        if ($data['Object']['distribution'] != 4) {
          echo $distributionLevels[$data['Object']['distribution']];
        } else {
          echo h($sg['SharingGroup']['name']);
        }
      ?><br />
      <span class="bold">Comment</span>: <?php echo h($data['Object']['comment']); ?><br />
      <span class="bold">Attributes</span>:<br />
      <?php
        $attributeFields = array('category', 'type', 'value', 'to_ids' , 'comment', 'uuid', 'distribution', 'sharing_group_id');
        if (!empty($data['Attribute'])):
          foreach ($data['Attribute'] as $attribute):
            echo '<span class="bold" style="margin-left:2em;">' . h($attribute['object_relation']) . ':</span><br />';
            foreach ($attributeFields as $field):
              if ($field == 'to_ids') $attribute[$field] = $attribute[$field] ? 'Yes' : 'No';
                if (isset($attribute[$field])):
      ?>
                <span class="bold" style="margin-left:4em;"><?php echo Inflector::humanize($field);?></span>: <?php echo h($attribute[$field]); ?><br />
      <?php
              endif;
            endforeach;
          endforeach;
        endif;
      ?>
    </div>
  <?php
    echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
  ?>
    <a href="<?php echo $baseurl . '/events/view/' . h($event['Event']['id']); ?>" style="margin-left:10px;" class="btn btn-inverse">Cancel</a>
  <?php
    echo $this->Form->end();
  ?>

</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'addObject', 'event' => $event));
?>
