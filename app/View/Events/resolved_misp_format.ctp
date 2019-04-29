<div class="index">
    <h2><?php echo h($title); ?></h2>
    <?php
        $event_id = $event['Event']['id'];
        $url = '/events/handleModuleResults/' . $event_id;
        echo $this->Form->create('Event', array('url' => $url, 'class' => 'mainForm'));
        $formSettings = array(
            'type' => 'hidden',
            'value' => json_encode($event, true)
        );
        echo $this->Form->input('data', $formSettings);
        echo $this->Form->input('JsonObject', array(
                'label' => false,
                'type' => 'text',
                'style' => 'display:none;',
                'value' => ''
        ));
        if (!isset($importComment)) {
            $importComment = $attributeValue . ': Enriched via the ' . $module . ' module';
        }
        echo $this->Form->input('default_comment', array(
                'label' => false,
                'type' => 'text',
                'style' => 'display:none;',
                'value' => $importComment
        ));
        echo $this->Form->end();
        $objects_array = array();
        foreach (array('Attribute', 'Object') as $field) {
            if (!empty($event[$field])) {
                $objects_array[] = strtolower($field) . 's';
            }
        }
        if (empty($objects_array)) {
            echo '<p>Results from the enrichment module for this attribute are empty.</p>';
        } else {
            $scope = join(' and ', $objects_array);
            echo '<p>Below you can see the ' . $scope . 'that are to be created from the results of the enrichment module.</p>';
        }
        $attributeFields = array('category', 'type', 'value', 'uuid');
        if (!empty($event['Object'])) {
    ?>
    <div class='MISPObjects' style="margin-bottom:40px;">
      <h3><?php echo __('Objects'); ?></h3>
      <?php
            foreach ($event['Object'] as $o => $object) {
      ?>
      <div class='MISPObject'>
        <table style="width:25%;">
          <tbody>
            <?php if(!empty($object['id'])) { ?>
            <tr>
              <td class="bold"><?php echo __('ID');?></td>
              <td class='ObjectID'><?php echo h($object['id']); ?></td>
            </tr>
            <?php
                }
                if (!empty($object['template_version'])) {
            ?>
            <div style="display:none;" class="TemplateVersion"><?php echo h($object['template_version']); ?></div>
            <?php
                }
                if (!empty($object['template_uuid'])) {
            ?>
            <div style="display:none;" class="TemplateUUID"><?php echo h($object['template_uuid']); ?></div>
            <?php } ?>
            <tr>
              <td class="bold"><?php echo __('Name');?></td>
              <td class='ObjectName'><?php echo h($object['name']); ?></td>
            </tr>
            <tr>
              <td class="bold"><?php echo __('Meta Category');?></td>
              <td class='ObjectMetaCategory'><?php echo h($object['meta-category']); ?></td>
            </tr>
            <tr>
              <td class="bold"><?php echo __('UUID');?></td>
              <td class='ObjectUUID' style='height:20px;width:60px;'><?php echo h($object['uuid']); ?></td>
            </tr>
            <tr>
              <td class="bold"><?php echo __('Distribution');?></td>
              <td style="width:60px;text-align:center;">
                <select class='ObjectDistribution' style='padding:0px;height:20px;margin-bottom:0px;'>
                  <?php
                    foreach ($distributions as $distKey => $distValue) {
                        echo '<option value="' . h($distKey) . '" ' . ($distKey == $object['distribution'] ? 'selected="selected"' : '') . '>' . h($distValue) . '</option>';
                    }
                  ?>
                </select>
                <div style="display:none;">
                  <select class='ObjectSharingGroup' style='padding:0px;height:20px;margin-top:3px;margin-bottom:0px;'>
                    <?php
                      foreach ($sgs as $sgKey => $sgValue) {
                          echo '<option value="' . h($sgKey) . '" ' . ($sgKey == $object['sharing_group_id'] ? 'selected="selected"' : '') . '>' . h($sgValue) . '</option>';
                      }
                    ?>
                  </select>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
        <?php if (!empty($object['ObjectReference'])) { ?>
        <tr>
          <td class="bold"><?php echo __('References:');?></td>
        </tr>
        <table class="ObjectReferences" style="margin-bottom:0px;text-align:left;width:50%;">
          <thead>
            <th><?php echo __('Relationship'); ?></th>
            <th><?php echo __('Referenced name/type'); ?></th>
            <th><?php echo __('Referenced uuid'); ?></th>
          </thead>
          <tbody>
            <?php
                    foreach ($object['ObjectReference'] as $reference) {
                        echo '<tr class="ObjectReference">';
                        echo '<td class="Relationship">' . h($reference['relationship_type']) . '</td>';
                        $referenced_uuid = $reference['referenced_uuid'];
                        foreach ($event['Object'] as $object_reference) {
                            if ($referenced_uuid === $object_reference['uuid']) {
                                $name = $object_reference['name'];
                                break;
                            }
                        }
                        if (!isset($name)) {
                            foreach ($event['Attribute'] as $attribute_reference) {
                                if ($referenced_uuid === $attribute_reference['uuid']) {
                                    $name = $attribute_reference['type'];
                                    break;
                                }
                            }
                            if (!isset($name)) {
                                $name = '';
                            }
                        }
                        echo '<td>' . h($name) . '</td>';
                        unset($name);
                        echo '<td class="ReferencedUUID">' . h($referenced_uuid) . '</td>';
                        echo '</tr>';
                    }
            ?>
          </tbody>
        </table>
        <?php
                }
                if (!empty($object['Attribute'])) {
        ?>
        <table class="ObjectAttributes table table-condensed table-striped" style="text-align:left;margin-bottom:20px;">
          <thead>
            <th><?php echo __('Attribute');?></th>
            <th><?php echo __('Category');?></th>
            <th><?php echo __('Type');?></th>
            <th><?php echo __('Value');?></th>
            <th><?php echo __('UUID');?></th>
            <th><?php echo __('IDS');?></th>
            <th><?php echo __('Disable Correlation');?></th>
            <th><?php echo __('Comment');?></th>
            <th><?php echo __('Distribution');?></th>
          </thead>
          <tbody>
            <?php
                    foreach ($object['Attribute'] as $a => $attribute) {
                        echo '<tr class="ObjectAttribute">';
                        echo '<td class="ObjectRelation">' . h($attribute['object_relation']) . '</td>';
                        foreach ($attributeFields as $field) {
                            echo '<td class="Attribute' . ucfirst($field) . '">' . (isset($attribute[$field]) ? h($attribute[$field]) : '') . '</td>';
                        }
            ?>
            <td class="short" style="width:40px;text-align:center;">
              <input type="checkbox" class="AttributeToIds" <?php if (!empty($attribute['to_ids'])) echo 'checked'; ?>/>
            </td>
            <td class="short" style="width:40px;text-align:center;">
              <input type="checkbox" class="AttributeDisableCorrelation" <?php if (!empty($attribute['disable_correlation'])) echo 'checked'; ?>/>
            </td>
            <td class="short">
              <input type="text" class="AttributeComment" style="padding:0px;height:20px;margin-bottom:0px;" placeholder="<?php echo h($importComment); ?>" <?php if (!empty($attribute['comment'])) echo 'value="' . h($attribute['comment']) . '"';?>/>
            </td>
            <td class="short" style="width:40px;text-align:center;">
              <select class='AttributeDistribution' style='padding:0px;height:20px;margin-bottom:0px;'>
                <?php
                        foreach ($distributions as $distKey => $distValue) {
                            echo '<option value="' . h($distKey) . '" ' . ($distKey == $attribute['distribution'] ? 'selected="selected"' : '') . '>' . h($distValue) . '</option>';
                        }
                ?>
              </select>
              <div style="display:none;">
                <select class='AttributeSharingGroup' style='padding:0px;height:20px;margin-top:3px;margin-bottom:0px;'>
                  <?php
                        foreach ($sgs as $sgKey => $sgValue) {
                            echo '<option value="' . h($sgKey) . '" ' . ($sgKey == $attribute['sharing_group_id'] ? 'selected="selected"' : '') . '>' . h($sgValue) . '</option>';
                        }
                  ?>
                </select>
              </div>
            </td>
            <?php
                        echo '</tr>';
                    }
                }
            ?>
          </tbody>
        </table>
      </div>
      <?php } ?>
    </div>
    <?php
        }
        if (!empty($event['Attribute'])) {
    ?>
    <div class='MISPAttributes'>
      <h3><?php echo __('Attributes'); ?></h3>
      <table class="table table-condensed table-stripped">
        <thead>
          <th><?php echo __('Category');?></th>
          <th><?php echo __('Type');?></th>
          <th><?php echo __('Value');?></th>
          <th><?php echo __('UUID');?></th>
          <th><?php echo __('IDS');?></th>
          <th><?php echo __('Disable Correlation');?></th>
          <th><?php echo __('Comment');?></th>
          <th><?php echo __('Distribution');?></th>
        </thead>
        <tbody>
          <?php
            foreach ($event['Attribute'] as $a => $attribute) {
                echo '<tr class="MISPAttribute">';
                foreach (array('category', 'type') as $field) {
                    $field_header = 'class="Attribute' . ucfirst($field);
                    if (isset($attribute[$field])) {
                        if (is_array($attribute[$field])) {
                            echo '<td class="short" style="width:40px;text-align:center;"><select ' . $field_header . 'Select"  style="padding:0px;height:20px;margin-bottom:0px;">';
                            foreach ($attribute[$field] as $v => $value) {
                                echo '<option value="' . h($value) . '" ' . ($v ? '' : 'selected="selected"') . '>' . h($value) . '</option>';
                            }
                            echo '</select></td>';
                        } else {
                            echo '<td ' . $field_header . '">' . h($attribute[$field]) . '</td>';
                        }
                    } else {
                        echo '<td ' . $field_header . '"></td>';
                    }
                }
                foreach (array('value', 'uuid') as $field) {
                    echo '<td class="Attribute' . ucfirst($field) . '">' . (isset($attribute[$field]) ? h($attribute[$field]) : '') . '</td>';
                }
          ?>
          <td class="short" style="width:40px;text-align:center;">
            <input type="checkbox" class="AttributeToIds" <?php if (isset($attribute['to_ids']) && $attribute['to_ids']) echo 'checked'; ?>/>
          </td>
          <td class="short" style="width:40px;text-align:center;">
            <input type="checkbox" class="AttributeDisableCorrelation" <?php if (isset($attribute['disable_correlation']) && $attribute['disable_correlation']) echo 'checked'; ?>/>
          </td>
          <td class="short">
            <input type="text" class="AttributeComment" style="padding:0px;height:20px;margin-bottom:0px;" placeholder="<?php echo h($importComment); ?>" <?php if (!empty($attribute['comment'])) echo 'value="' . h($attribute['comment']) . '"';?>/>
          </td>
          <td class="short" style="width:40px;text-align:center;">
            <select class='AttributeDistribution' style='padding:0px;height:20px;margin-bottom:0px;'>
            <?php
                foreach ($distributions as $distKey => $distValue) {
                    echo '<option value="' . h($distKey) . '" ' . ($distKey == $attribute['distribution'] ? 'selected="selected"' : '') . '>' . h($distValue) . '</option>';
                }
            ?>
            </select>
            <div style="display:none;">
              <select class='AttributeSharingGroup' style='padding:0px;height:20px;margin-top:3px;margin-bottom:0px;'>
                <?php
                foreach ($sgs as $sgKey => $sgValue) {
                    echo '<option value="' . h($sgKey) . '" ' . ($sgKey == $attribute['sharing_group_id'] ? 'selected="selected"' : '') . '>' . h($sgValue) . '</option>';
                }
                ?>
              </select>
            </div>
          </td>
          <?php
                echo '</tr>';
            }
          ?>
        </tbody>
      </table>
    </div>
    <?php } ?>
    <span>
      <button class="btn btn-primary" style="float:left;" onClick="moduleResultsSubmit('<?php echo h($event_id); ?>');"><?php echo __('Submit'); ?></button>
    </span>
</div>
<script type="text/javascript">
    $(document).ready(function() {
      $('.AttributeDistribution').change(function() {
          if ($(this).val() == 4) {
              $(this).next().show();
          } else {
              $(this).next().hide();
          }
      });
      $('.ObjectDistribution').change(function() {
          if ($(this).val() == 4) {
              $(this).next().show();
          } else {
              $(this).next().hide();
          }
      });
    });
</script>
<?php
    if (!isset($menuItem)) {
        $menuItem = 'freetextResults';
    }
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => $menuItem));
?>
