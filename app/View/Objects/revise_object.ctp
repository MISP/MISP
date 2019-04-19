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
                  $simple_flattened_object = array();
                  $simple_flattened_object_noval = array();
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

    <?php echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary')); ?>
    <a href="<?php echo $baseurl . '/events/view/' . h($event['Event']['id']); ?>" style="margin-left:10px;" class="btn btn-inverse"><?php echo __('Cancel');?></a>
    <?php if (!empty($similar_objects) && $action !== 'edit'): ?>
        <?php
            // debug($data);
         ?>
        <?php echo '<h3 style="margin-top: 20px;">' . __('The event have similar object.') . '</h3>'; ?>
        <?php echo '<h5>' . __('Would you like to merge your new object with one of the following?') . '</h5>'; ?>
        <div class="row" style="margin-bottom: 20px;">
        <?php foreach ($similar_objects as $i => $object): ?>
            <?php
                if ($object['Object']['template_version'] < $template['ObjectTemplate']['version']) {
                    $temp_comparison = 'below';
                } else if ($object['Object']['template_version'] > $template['ObjectTemplate']['version']) {
                    $temp_comparison = 'above';
                } else {
                    $temp_comparison = 'equal';
                }
            ?>
            <div style="border: 1px solid #3465a4 ; border-radius: 5px; <?php echo $temp_comparison == 'above' ? 'filter: grayscale(60%);' : ''; ?>" class="span5 similarObjectPanel">
                <?php
                if ($temp_comparison == 'below') {
                    $btn_style = 'btn-warning';
                    $temp_text = __('Update template and merge');
                } else if ($temp_comparison == 'above') {
                    $btn_style = 'btn-danger';
                    $temp_text = __('Can\'t merge due to template version');
                } else {
                    $temp_text = __('Merge');
                    $btn_style = 'btn-success';
                }
                ?>
                <div class="blueElement" style="padding: 4px 5px;">
                    <div style="text-align: center;">
                        <input type="button" class="btn <?php echo $btn_style; ?>" onclick="setMergeObject(<?php echo h($object['Object']['id']) ?>)" value="<?php echo $temp_text; ?>" <?php echo $temp_comparison == 'above' ? 'disabled' : ''; ?>></input>
                    </div>
                    <div>
                        <span class="bold"><?php echo __('ID') . ':'; ?></span>
                        <a href="<?php echo $baseurl . '/objects/edit/' . h($object['Object']['id']); ?>" style="color: white;"><?php echo h($object['Object']['id']); ?></a>
                    </div>
                    <div>
                        <span class="bold"><?php echo __('Name') . ':'; ?></span>
                        <span><?php echo h($object['Object']['name']); ?></span>
                    </div>
                    <div>
                        <span class="bold"><?php echo __('Description') . ':'; ?></span>
                        <span><?php echo h($object['Object']['description']); ?></span><br>
                    </div>
                    <div>
                        <span class="bold"><?php echo __('Distribution') . ':'; ?></span>
                        <span><?php echo h($object['Object']['distribution']); ?></span>
                    </div>
                    <?php
                        $temp_style = '';
                        if ($temp_comparison == 'below') {
                            $temp_style .= 'background-color: #fcf8e3; color: black; padding: 2px;';
                        } else if ($temp_comparison == 'above') {
                            $temp_style .= 'background-color: #bd362f; color: white; padding: 2px;';
                        }
                    ?>
                    <div style="<?php echo $temp_style ?> border-radius: 3px;" data-templatecomparison="<?php echo $temp_comparison; ?>">
                        <span class="bold"><?php echo __('Template version') . ':'; ?></span>
                        <span><?php echo h($object['Object']['template_version']); ?></span>
                    </div>
                </div>
                <?php $flattened_ids_in_similar_object = array(); ?>
                <table class="table table-striped table-condensed" style="margin-bottom: 0px;">
                    <tbody>
                        <?php foreach ($object['Attribute'] as $attribute): ?>
                            <?php
                                $simple_flattened_similar_attribute = h($attribute['object_relation']) . '.' . h($attribute['type']) . '.' .h($attribute['value']);
                                $simple_flattened_similar_attribute_noval = h($attribute['object_relation']) . '.' . h($attribute['type']);
                                $flattened_ids_in_similar_object[$simple_flattened_similar_attribute_noval] = $attribute['id'];
                                $classname = '';
                                $to_highlight = '';
                                $title = '';
                                if (
                                    isset($simple_flattened_attribute_noval[$simple_flattened_similar_attribute_noval])
                                    && !isset($simple_flattened_attribute[$simple_flattened_similar_attribute])
                                ) { // Not overridable attribute
                                    $classname = 'warning';
                                    $title = __('This attribute will be preserved after the merge.');
                                    $to_highlight = $simple_flattened_similar_attribute_noval;
                                } else if (!isset($simple_flattened_attribute[$simple_flattened_similar_attribute])) { // Attribute not present in the revised object
                                    $classname = 'info';
                                    $title = __('This attribute is contain only by this similar object. It will remain untouched.');
                                }
                            ?>
                            <tr class="<?php echo $classname ?>" data-tohighlight="<?php echo h($to_highlight); ?>" title="<?php echo $title; ?>">
                                <td><?php echo h($attribute['object_relation']); ?></td>
                                <td><?php echo h($attribute['category']); ?></td>
                                <td><?php echo h($attribute['type']); ?></td>
                                <td><?php echo h($attribute['value']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <?php $attribute_ids_to_inject = array_values(array_diff_key($simple_flattened_attribute_noval, $flattened_ids_in_similar_object)); ?>
                <?php if (!empty($attribute_ids_to_inject)): ?>
                    <table class="table table-striped table-condensed" style="margin-bottom: 3px; border-top: 2px dashed #3465a4">
                        <tbody>
                            <?php foreach ($attribute_ids_to_inject as $attribute_id): ?>
                                <?php $attribute = $data['Attribute'][$attribute_id]; ?>
                                <tr class="success" title="<?php echo __('This attribute will be added to this similar object after the merge.'); ?>">
                                    <td class="apply_css_arrow"><?php echo h($attribute['object_relation']); ?></td>
                                    <td><?php echo h($attribute['category']); ?></td>
                                    <td><?php echo h($attribute['type']); ?></td>
                                    <td><?php echo h($attribute['value']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
        </div>
    <?php endif; ?>
  <?php
    echo $this->Form->end();
  ?>

</div>

<script>
function setMergeObject(object_id) {
    var cur_object = $('input[name="data[Object][data]"]').val();
    window.location = "<?php echo $baseurl . '/objects/edit/'; ?>" + object_id + "/attributeToInject:" + btoa(cur_object);
}

function highlight_rows($panel, state) {
    $('#attribute_table').find('tr.error').removeClass('error').attr('title', '');
    var rows = $panel.find('tr.warning');
    var to_highlight = [];
    rows.each(function() {
        to_highlight.push($(this).data().tohighlight);
    });
    to_highlight.forEach(function(curflat) {
        var $row_to_highlight = $('#attribute_table').find('tr[data-curflatnoval="' + curflat + '"]');
        if (state === undefined) {
            $row_to_highlight.addClass('error');
            $row_to_highlight.attr('title', '<?php echo __('This attribute will NOT be merged into the similar object as it is conflicting with another attribute.'); ?>')
        } else if (state) {
            $row_to_highlight.addClass('error');
        } else {
            $row_to_highlight.removeClass('error');
        }
    });
    // $('#attribute_table').find('tr.error').add($panel.find('tr.success, tr.warning, tr.info')).tooltip();
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
            un_highlight_time = setTimeout(function () { $('#attribute_table').find('tr.error').removeClass('error').attr('title', ''); }, 1000);
        }
    );
});
</script>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'addObject', 'event' => $event));
?>
