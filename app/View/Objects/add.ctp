<div class="<?php if (!isset($ajax) || !$ajax) echo 'form';?>">
<?php
    $url = ($action == 'add') ? '/objects/revise_object/add/' . $event['Event']['id'] . '/' . $template['ObjectTemplate']['id'] : '/objects/revise_object/edit/' . $event['Event']['id'] . '/' . $template['ObjectTemplate']['id'] . '/' . h($object['Object']['id']);
    echo $this->Form->create('Object', array('id', 'url' => $url, 'enctype' => 'multipart/form-data'));
?>
<h3><?php echo ucfirst($action) . ' ' . Inflector::humanize(h($template['ObjectTemplate']['name'])) . __(' Object'); ?></h3>
<div class="row-fluid" style="margin-bottom:10px;">
  <dl class="span8">
    <dt><?php echo __('Object Template');?></dt>
    <dd>
      <?php
        echo Inflector::humanize(h($template['ObjectTemplate']['name'])) . ' v' . h($template['ObjectTemplate']['version']);
        if ($action == 'edit' && !$updateTemplate && $newer_template_version !== false): ?>
            <a class="btn btn-mini btn-primary useCursorPointer" title="<?php echo __('Update the template of this object to the newer version: ') . h($newer_template_version) ?>" href="<?php echo $baseurl . '/objects/edit/' . h($object['Object']['id']) . '/1'; ?>">
                <span class="fa fa-arrow-circle-up"></span>
                <?php echo __('Update template') ?>
            </a>
        <?php endif; ?>
      &nbsp;
    </dd>
    <dt><?php echo __('Description');?></dt>
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
    <dt><?php echo __('Meta category');?></dt>
    <dd>
      <?php echo Inflector::humanize(h($template['ObjectTemplate']['meta-category'])); ?>&nbsp;
    </dd>
    <dt><?php echo __('Distribution');?></dt>
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
    <dt><?php echo __('Comment');?></dt>
    <dd>
      <?php
        echo $this->Form->input('Object.comment', array(
          'type' => 'textarea',
          'style' => 'height:20px;width:400px;',
          'required' => false,
          'allowEmpty' => true,
          'label' => false,
          'div' => false
        ));
      ?>
    </dd>
  </dl>
</div>
<?php
    if (!empty($template['warnings'])):
    ?>
        <span class="red bold"><?php echo __('Warning, issues found with the template');?>:</span>
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
    <th><?php echo __('Save');?></th>
    <th><?php echo __('Name :: type');?></th>
        <th><?php echo __('Description');?></th>
    <th><?php echo __('Category');?></th>
    <th><?php echo __('Value');?></th>
    <th><?php echo __('IDS');?></th>
        <th><?php echo __('Disable Correlation');?></th>
    <th><?php echo __('Distribution');?></th>
    <th><?php echo __('Comment');?></th>
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
                    <span id="submitButton" class="btn btn-primary" title="<?php echo __('Submit');?>" role="button" tabindex="0" aria-label="<?php echo __('Submit');?>" onClick="submitPopoverForm('<?php echo $event_id;?>', 'add')"><?php echo __('Submit');?></span>
                </td>
                <td style="width:540px;margin-bottom:0px;">
                    <p style="color:red;font-weight:bold;display:none;text-align:center;margin-bottom:0px;" id="warning-message"><?php echo __('Warning: You are about to share data that is of a classified nature. Make sure that you are authorised to share this.');?></p>
                </td>
                <td style="vertical-align:bottom;">
                    <span class="btn btn-inverse" title="<?php echo __('Cancel');?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" id="cancel_attribute_add"><?php echo __('Cancel');?></span>
                </td>
                </tr>
            </table>
        </div>
    <?php
        else:
    ?>
        <p style="color:red;font-weight:bold;display:none;" id="warning-message"><?php echo __('Warning: You are about to share data that is of a classified nature. Make sure that you are authorised to share this.');?></p>
    <?php
            echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
        endif;
        echo $this->Form->end();
    ?>
    <?php debug($updateable_attribute); ?>
    <?php debug($not_updateable_attribute); ?>
</div>

<?php if ($updateTemplate || isset($revised_object)): //add control panel (same as distribution network) and fill with data ?>
        <div class="fixedRightPanel" style="width: unset; height:unset; background-color: #ffffff">
            <?php if ($updateTemplate): ?>
                <div class="fixedRightPanelHeader useCursorPointer" style="box-shadow: 0px 0px 6px #B2B2B2;margin-bottom: 2px;width: 100%;overflow: hidden; padding: 5px;">
                    <i class="fas fa-chevron-circle-down"></i>
                    <span style="margin-left: 5px; display: inline-block; font-size: large;"><?php echo __('Pre-update object\'s template'); ?></span>
                </div>
                <div class="row" style="max-height: 800px; max-width: 800px; overflow: auto; padding: 15px;">
                    <div style="border: 1px solid #3465a4 ; border-radius: 5px;" class="span5">
                        <div class="blueElement" style="padding: 4px 5px;">
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
                            <div style="border-radius: 3px;">
                                <span class="bold"><?php echo __('Template version') . ':'; ?></span>
                                <span><?php echo h($object['Object']['template_version']); ?></span>
                            </div>
                        </div>
                        <table class="table table-striped table-condensed" style="margin-bottom: 0px;">
                            <tbody>
                                <?php foreach ($not_updateable_attribute as $attribute): ?>
                                    <tr class="error" title="<?php echo __('Can not be merged automatically'); ?>">
                                        <td><?php echo h($attribute['object_relation']); ?></td>
                                        <td><?php echo h($attribute['category']); ?></td>
                                        <td><?php echo h($attribute['type']); ?></td>
                                        <td><?php echo h($attribute['value']); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                                <?php foreach ($updateable_attribute as $attribute): ?>
                                    <tr class="success" title="<?php echo __('Can be merged automatically. Injection done.'); ; ?>">
                                        <td><?php echo h($attribute['object_relation']); ?></td>
                                        <td><?php echo h($attribute['category']); ?></td>
                                        <td><?php echo h($attribute['type']); ?></td>
                                        <td><?php echo h($attribute['value']); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            <?php endif; ?>
            <?php if (isset($revised_object)): ?>
                <div class="fixedRightPanelHeader useCursorPointer" style="box-shadow: 0px 0px 6px #B2B2B2;margin-bottom: 2px;width: 100%;overflow: hidden; margin-top: 10px; padding: 5px;">
                    <i class="fas fa-chevron-circle-down"></i>
                    <span style="margin-left: 5px; display: inline-block; font-size: large;"><?php echo __('Attributes to merge'); ?></span>
                </div>
                <div class="row" style="max-height: 800px; max-width: 800px; overflow: auto; padding: 15px;">
                    <div style="border: 1px solid #3465a4 ; border-radius: 5px;" class="span5">
                        <table class="table table-striped table-condensed" style="margin-bottom: 0px;">
                            <tbody>
                                <?php foreach ($revised_object['notMergeable'] as $attribute): ?>
                                    <tr class="error" title="<?php echo __('Can not be merged automatically'); ?>">
                                        <td><?php echo h($attribute['object_relation']); ?></td>
                                        <td><?php echo h($attribute['category']); ?></td>
                                        <td><?php echo h($attribute['type']); ?></td>
                                        <td>
                                            <?php echo h($attribute['value']); ?>
                                            <i class="fas fa-question-circle" title="<?php echo __('Current value: ') . h($attribute['current_value']); ?>"></i>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                <?php foreach ($revised_object['mergeable'] as $attribute): ?>
                                    <tr class="success" title="<?php echo __('Can be merged automatically. Injection done.'); ; ?>">
                                        <td><?php echo h($attribute['object_relation']); ?></td>
                                        <td><?php echo h($attribute['category']); ?></td>
                                        <td><?php echo h($attribute['type']); ?></td>
                                        <td><?php echo h($attribute['value']); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            <?php endif; ?>
        </div>
<?php endif; ?>


<?php
    if (!$ajax) {
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'addObject', 'event' => $event));
    }
?>
<script type="text/javascript">
  var rows = <?php echo json_encode($row_list, true); ?>;
  $(document).ready(function() {
    enableDisableObjectRows(rows);
        $(".Attribute_value_select").each(function() {
      checkAndEnable($(this).parent().find('.Attribute_value'), $(this).val() == '<?php echo __('Enter value manually');?>');
    });
    $(".Attribute_distribution_select").change(function() {
      checkAndEnable($(this).parent().find('.Attribute_sharing_group_id_select'), $(this).val() == 4);
    });

    $(".Object_distribution_select").change(function() {
      checkAndEnable($(this).parent().find('.Object_sharing_group_id_select'), $(this).val() == 4);
    });
    $(".Attribute_value_select").change(function() {
      checkAndEnable($(this).parent().find('.Attribute_value'), $(this).val() == '<?php echo __('Enter value manually');?>');
    });
        $('.add_attribute_row').click(function() {
            var selector = $(this).data('target');
            var count = $(this).parent().children(selector).length;
            $(this).parent().children(selector).first().clone().appendTo($(this).parent()).insertBefore($('.add_unlocked_field'));
        });
  });
  $('.fixedRightPanel .fixedRightPanelHeader').click(function() {
      $(this).next().toggle('blind');
      return false;
  });
</script>
