<div class="index">
    <h2><?php echo h($title); ?></h2>
    <?php
        $url = '/events/handleModuleResults/' . $event['Event']['id'];
        echo $this->Form->create('Event', array('url' => array('controller' => 'events', 'action' => 'handleModuleResults', $event['Event']['id'])));
        $formSettings = array(
            'type' => 'hidden',
            'value' => json_encode($event, true)
        );
        echo $this->form->input('data', $formSettings);
        $scope = !empty($proposals) ? 'proposals of' : '';
        $objects_array = array();
        if (isset($event['Attribute'])) {
            array_push($objects_array, 'attributes');
        }
        if (isset($event['Object'])) {
            array_push($objects_array, 'objects');
        }
        if (isset($resultArray) && !in_array('attributes', $objects_array, true) && in_array('objects', $objects_array, true)) {
            $scope .= __('simplified attributes and');
        }
        $scope .= !empty($objects_array) ? join(' and ', $objects_array) : 'simplified attributes';
        if (!isset($importComment)) {
            $importComment = $attributeValue . ': Enriched via the ' . $module . ' module';
        }
    ?>
    <p><?php echo __('Below you can see the %s that are to be created, from the results of the enrichment module.', $scope);?></p>
    <div style="margin-bottom:20px;">
        <?php
            $attributeFields = array('category', 'type', 'value', 'uuid');
            $defaultDistribution = 5;
            if (!empty(Configure::read('MISP.default_attribute_distribution'))) {
                $defaultDistribution = Configure::read('MISP.default_attribute_distribution');
                if ($defaultDistribution == 'event') {
                    $defaultDistribution = 5;
                }
            }
            if (isset($event['Object'])) {
        ?>
        <table class="table table-condensed table-stripped">
        <h3><?php echo __('Objects'); ?></h3>
        </table>
        <?php
                foreach ($event['Object'] as $o => $object) {
        ?>
        <table class="table table-condensed table-stripped">
          <tbody>
            <tr>
              <td class="bold"><?php echo __('Name');?></td>
              <td><?php echo h($object['name']); ?></td>
            </tr>
            <tr>
              <table class="table table-condensed table-striped">
                <thead>
                  <th><?php echo __('Attribute');?></th>
                  <th><?php echo __('Category');?></th>
                  <th><?php echo __('Type');?></th>
                  <th><?php echo __('Value');?></th>
                  <th><?php echo __('UUID');?></th>
                  <th><?php echo __('To IDS');?></th>
                  <th><?php echo __('Comment');?></th>
                  <th><?php echo __('Distribution');?></th>
                </thead>
                <tbody>
                  <?php
                    if (!empty($object['Attribute'])) {
                        foreach ($object['Attribute'] as $a => $attribute) {
                            echo '<tr>';
                            echo '<td>' . h($attribute['object_relation']) . '</td>';
                            if (isset($attribute['distribution'])) {
                                if ($attribute['distribution'] != 4) {
                                    $attribute['distribution'] = $distributions[$attribute['distribution']];
                                } else {
                                    $attribute['distribution'] = $sgs[$attribute['sharing_group_id']];
                                }
                            } else {
                                $attribute['distribution'] = $distributions[$defaultDistribution];
                            }
                            foreach ($attributeFields as $field) {
                                if (isset($attribute[$field])) {
                                    echo '<td>' . h($attribute[$field]) . '</td>';
                                } else {
                                    echo '<td></td>';
                                }
                            }
                  ?>
                  <td class="short" style="width:40px;text-align:center;">
                    <input type="checkbox" id="<?php echo 'Object' . $o . 'Attribute' . $a . 'To_ids'; ?>" <?php if (isset($attribute['to_ids']) && $attribute['to_ids']) echo 'checked'; ?> class="idsCheckbox"/>
                  </td>
                  <td class="short">
                    <input type="text" class="freetextCommentField" id="<?php echo 'Object' . $o . 'Attribute' . $a . 'Comment'; ?>" style="padding:0px;height:20px;margin-bottom:0px;" placeholder="<?php echo h($importComment); ?>" <?php if (isset($attribute['comment']) && $attribute['comment'] !== false) echo 'value="' . h($attribute['comment']) . '"';?>/>
                  </td>
                  <td class="short" style="width:40px;text-align:center;">
                    <select id="<?php echo 'Object' . $o . 'Attribute' . $a . 'Distribution'; ?>" class='distributionToggle' style='padding:0px;height:20px;margin-bottom:0px;'>
                      <?php
                            foreach ($distributions as $distKey => $distValue) {
                                echo '<option value="' . $distKey . '" ' . ($distValue == $attribute['distribution'] ? 'selected="selected"' : '') . '>' . $distValue . '</option>';
                          }
                      ?>
                    </select>
                  </td>
                  <?php
                            echo '</tr>';
                        }
                    }
                  ?>
                </tbody>
              </table>
            </tr>
          </tbody>
        </table>
        <?php
                }
            }
            if (isset($event['Attribute'])) {
        ?>
        <table class="table table-condensed table-stripped">
        <h3><?php echo __('Attributes'); ?></h3>
          <thead>
            <th><?php echo __('Category');?></th>
            <th><?php echo __('Type');?></th>
            <th><?php echo __('Value');?></th>
            <th><?php echo __('UUID');?></th>
            <th><?php echo __('To IDS');?></th>
            <th><?php echo __('Comment');?></th>
            <th><?php echo __('Distribution');?></th>
          </thead>
          <tbody>
          <?php
                foreach ($event['Attribute'] as $a => $attribute) {
                    echo '<tr>';
                    if (isset($attribute['distribution'])) {
                        $attribute['distribution'] = ($attribute['distribution'] != 4 ? $distributions[$attribute['distribution']] : $sgs[$attribute['sharing_group_id']]);
                    } else {
                        $attribute['distribution'] = $distributions[$defaultDistribution];
                    }
                    foreach ($attributeFields as $field) {
                        if (isset($attribute[$field])) {
                            echo '<td>' . h($attribute[$field]) . '</td>';
                        } else {
                            echo '<td></td>';
                        }
                    }
          ?>
          <td class="short" style="width:40px;text-align:center;">
            <input type="checkbox" id="<?php echo 'Attribute' . $a . 'To_ids'; ?>" <?php if (isset($attribute['to_ids']) && $attribute['to_ids']) echo 'checked'; ?> class='idsCheckbox'/>
          </td>
          <td class="short">
            <input type="text" class="freetextCommentField" id="<?php echo 'Attribute' . $a . 'Comment'; ?>" style="padding:0px;height:20px;margin-bottom:0px;" placeholder="<?php echo h($importComment); ?>" <?php if (isset($attribute['comment']) && $attribute['comment'] !== false) echo 'value="' . h($attribute['comment']) . '"';?>/>
          </td>
          <td class="short" style="width:40px;text-align:center;">
            <select id="<?php echo 'Attribute' . $a . 'Distribution'; ?>" class='distributionToggle' style='padding:0px;height:20px;margin-bottom:0px;'>
            <?php
                    foreach ($distributions as $distKey => $distValue) {
                        echo '<option value="' . $distKey . '" ' . ($distValue == $attribute['distribution'] ? 'selected="selected"' : '') . '>' . $distValue . '</option>';
                    }
            ?>
            </select>
          </td>
          <?php
                    echo '</tr>';
                }
            }
          ?>
          </tbody>
        </table>
    </div>
    <?php
            echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
            echo $this->Form->end();
    ?>
</div>
<?php
    if (!isset($menuItem)) {
        $menuItem = 'freetextResults';
    }
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => $menuItem));
?>
