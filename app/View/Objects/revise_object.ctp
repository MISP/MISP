<div class="form">
  <h3><?php echo __('Object pre-save review');?></h3>
  <p><?php echo __('Make sure that the below Object reflects your expectation before submiting it.');?></p>
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
      <table class="table table-condensed table-striped">
        <tbody>
          <tr>
            <td class="bold"><?php echo __('Name');?></td>
            <td><?php echo h($template['ObjectTemplate']['name']); ?></td>
          </tr>
          <tr>
            <td class="bold"><?php echo __('Meta-category');?></td>
            <td><?php echo h($template['ObjectTemplate']['meta-category']); ?></td>
          </tr>
          <tr>
            <td class="bold"><?php echo __('Distribution');?></td>
            <td><?php
              if ($data['Object']['distribution'] != 4) {
                echo $distributionLevels[$data['Object']['distribution']];
              } else {
                echo h($sharing_groups[$data['Object']['sharing_group_id']]['SharingGroup']['name']);
              }
            ?></td>
          </tr>
          <tr>
            <td class="bold"><?php echo __('Comment');?></td>
            <td><?php echo h($data['Object']['comment']); ?></td>
          </tr>
          <tr>
            <table class="table table-condensed table-striped">
              <thead>
                <th><?php echo __('Attribute');?></th>
                <th><?php echo __('Category');?></th>
                <th><?php echo __('Type');?></th>
                <th><?php echo __('Value');?></th>
                <th><?php echo __('To IDS');?></th>
                <th><?php echo __('Comment');?></th>
                <th><?php echo __('UUID');?></th>
                <th><?php echo __('Distribution');?></th>
              </thead>
              <tbody>
                <?php
                  $attributeFields = array('category', 'type', 'value', 'to_ids' , 'comment', 'uuid', 'distribution');
                  if (!empty($data['Attribute'])):
                    foreach ($data['Attribute'] as $attribute):
                      echo '<tr>';
                      echo '<td>' . h($attribute['object_relation']) . '</td>';
                      foreach ($attributeFields as $field):
                        if ($field == 'distribution') {
                          if ($attribute['distribution'] != 4) {
                            $attribute[$field] = $distributionLevels[$attribute['distribution']];
                          } else {
                            $attribute[$field] = $sharing_groups[$attribute['sharing_group_id']]['SharingGroup']['name'];
                          }
                        }
                        if ($field == 'to_ids') $attribute[$field] = $attribute[$field] ? __('Yes') : __('No');
                          if (isset($attribute[$field])):
                           echo '<td>'.h($attribute[$field]). '</td>';
                          else:
                           echo '<td></td>';
                          endif;
                      endforeach;
                      echo '</tr>';
                    endforeach;
                  endif;
                ?>
              </tbody>
            </table>
          </tr>
        </tbody>
      </table>
    </div>
  <?php
    echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
  ?>
    <a href="<?php echo $baseurl . '/events/view/' . h($event['Event']['id']); ?>" style="margin-left:10px;" class="btn btn-inverse"><?php echo __('Cancel');?></a>
  <?php
    echo $this->Form->end();
  ?>

</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'addObject', 'event' => $event));
?>
