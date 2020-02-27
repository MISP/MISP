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
    <div class='hidden'>
  <?php
    echo $this->Form->input('mergeIntoObject', array(
        'value' => 0,
        'div' => false
    ));
  ?>
  </div>
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
              <td class="bold"><?php echo __('Template version');?></td>
              <td><?php echo h($template['ObjectTemplate']['version']); ?></td>
          </tr>
          <tr>
            <td class="bold"><?php echo __('Comment');?></td>
            <td><?php echo h($data['Object']['comment']); ?></td>
          </tr>
          <td class="bold"><?php echo __('First seen');?></td>
            <td><?php echo h($data['Object']['first_seen']); ?></td>
          </tr>
          <tr>
            <td class="bold"><?php echo __('Last seen');?></td>
            <td><?php echo h($data['Object']['last_seen']); ?></td>
          </tr>
          <tr>
            <table id="attribute_table" class="table table-condensed table-striped">
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
                  $simple_flattened_attribute = array();
                  $simple_flattened_attribute_noval = array();
                  $attributeFields = array('category', 'type', 'value', 'to_ids' , 'comment', 'uuid', 'distribution');
                  if (!empty($data['Attribute'])):
                    foreach ($data['Attribute'] as $id => $attribute):
                      $cur_flat = h($attribute['object_relation']) . '.' . h($attribute['type']) . '.' .h($attribute['value']);
                      $cur_flat_noval = h($attribute['object_relation']) . '.' . h($attribute['type']);
                      $simple_flattened_attribute[$cur_flat] = $id;
                      $simple_flattened_attribute_noval[$cur_flat_noval] = $id;
                      echo sprintf('<tr data-curflat="%s" data-curflatnoval="%s">', h($cur_flat), h($cur_flat_noval));
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

    <?php echo $this->Form->button(__('Create new object'), array('class' => 'btn btn-primary')); ?>
    <a href="#" style="margin-left:10px;" class="btn btn-inverse" onclick="window.history.back();"><?php echo __('Back to review');?></a>
    <a href="<?php echo $baseurl . '/events/view/' . h($event['Event']['id']); ?>" style="margin-left:10px;" class="btn btn-inverse"><?php echo __('Cancel');?></a>
    <?php if (!empty($similar_objects) && $action !== 'edit'): ?>
        <?php echo '<h3 style="margin-top: 20px;">' . __('This event contains similar objects.') . '</h3>'; ?>
        <?php echo '<h5>' . __('Instead of creating a new object, would you like to merge your new object into one of the following?') . '</h5>'; ?>
        <div class="row" style="margin-bottom: 20px;">
        <?php foreach ($similar_objects as $object): ?>
            <?php
                echo $this->element('Objects/object_similarities', array(
                    'object' => $object,
                    'template' => $template,
                    'similar_object_similarity_amount' => $similar_object_similarity_amount,
                    'simple_flattened_attribute_noval' => $simple_flattened_attribute_noval,
                    'simple_flattened_attribute' => $simple_flattened_attribute,
                    'merge_button_functionname' => 'setMergeObject'
                ));
            ?>
        <?php endforeach; ?>
        <?php if ($similar_objects_count > $similar_objects_display_threshold): ?>
            <div class="span5" style="margin-top: 20px;display: inline-block;float: unset;">
                <div class="alert alert-info">
                    <h4><?php echo __('All similar objects not displayed...'); ?></h4>
                    <?php echo sprintf(__('%s Similar objects found. %s not displayed'), $similar_objects_count, $similar_objects_count-$similar_objects_display_threshold); ?>
                </div>
            </div>
        <?php endif; ?>
        </div>
    <?php endif; ?>
  <?php
    echo $this->Form->end();
  ?>

</div>

<script>
function setMergeObject(clicked) {
    var $clicked = $(clicked);
    var object_id = $clicked.data('objectid');
    var update_template = $clicked.data('updatetemplate');
    update_template = update_template === undefined ? false : update_template;
    var cur_object = $('input[name="data[Object][data]"]').val();
    window.location = "<?php echo $baseurl . '/objects/edit/'; ?>" + object_id + (update_template ? '/1' : '') + "/revised_object:" + btoa(cur_object);
}

function highlight_rows($panel, state) {
    $('#attribute_table').find('tr.error, tr.warning').removeClass('error warning').attr('title', '');
    var rows = $panel.find('tr.error, tr.warning');
    var to_highlight = [];
    rows.each(function() {
        var row_class = $(this).hasClass('error') ? 'error' : 'warning';
        to_highlight.push([$(this).data().tohighlight, row_class]);
    });
    to_highlight.forEach(function(arr) {
        var curflat = arr[0];
        var row_class = arr[1];
        var $row_to_highlight = $('#attribute_table').find('tr[data-curflatnoval="' + curflat + '"]');
        if (state === undefined) {
            $row_to_highlight.addClass(row_class);
            if (row_class == 'error') {
                $row_to_highlight.attr('title', '<?php echo __('This attribute will NOT be merged into the similar object as it is conflicting with another attribute.'); ?>')
            }
        } else if (state) {
            $row_to_highlight.addClass(row_class);
        } else {
            $row_to_highlight.removeClass(row_class);
        }
    });
}

var un_highlight_time;
$(document).ready(function() {
    $('.similarObjectPanel').hover(
        function() {
            var $panel = $(this);
            if (un_highlight_time !== undefined) {
                clearTimeout(un_highlight_time);
            }
            highlight_rows($panel);
        },
        function() {
            un_highlight_time = setTimeout(function () {
                $('#attribute_table').find('tr.error').removeClass('error').attr('title', '');
                $('#attribute_table').find('tr.warning').removeClass('warning').attr('title', '');
            }, 1000);
        }
    );
});
</script>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'addObject', 'event' => $event));
?>
