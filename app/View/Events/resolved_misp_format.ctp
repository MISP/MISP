<div class="index">
    <h2><?php echo h($title); ?></h2>
    <?php
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
    ?>
    <p><?php echo __('Below you can see the %s that are to be created, from the results of the enrichment module.', $scope);?></p>
    <div style="margin-bottom:20px;">
        <?php
            $attributeFields = array('category', 'type', 'value', 'to_ids', 'comment', 'uuid', 'distribution');
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
                foreach ($event['Object'] as $object) {
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
                  <th><?php echo __('To IDS');?></th>
                  <th><?php echo __('Comment');?></th>
                  <th><?php echo __('UUID');?></th>
                  <th><?php echo __('Distribution');?></th>
                </thead>
                <tbody>
                  <?php
                    if (!empty($object['Attribute'])) {
                        foreach ($object['Attribute'] as $attribute) {
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
                            if (isset($attribute['to_ids'])) {
                                $attribute['to_ids'] = ($attribute['to_ids'] ? __('Yes') : __('No'));
                            }
                            foreach ($attributeFields as $field) {
                                if (isset($attribute[$field])) {
                                    echo '<td>' . h($attribute[$field]) . '</td>';
                                } else {
                                    echo '<td></td>';
                                }
                            }
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
            <th><?php echo __('To IDS');?></th>
            <th><?php echo __('Comment');?></th>
            <th><?php echo __('UUID');?></th>
            <th><?php echo __('Distribution');?></th>
          </thead>
          <tbody>
          <?php
                foreach ($event['Attribute'] as $attribute) {
                    echo '<tr>';
                    if (isset($attribute['distribution'])) {
                        $attribute['distribution'] = ($attribute['distribution'] != 4 ? $distributions[$attribute['distribution']] : $sgs[$attribute['sharing_group_id']]);
                    } else {
                        $attribute['distribution'] = $distributions[$defaultDistribution];
                    }
                    if (isset($attribute['to_ids'])) {
                        $attribute['to_ids'] = ($attribute['to_ids'] ? __('Yes') : _('No'));
                    }
                    foreach ($attributeFields as $field) {
                        if (isset($attribute[$field])) {
                            echo '<td>' . h($attribute[$field]) . '</td>';
                        } else {
                            echo '<td></td>';
                        }
                    }
                    echo '</tr>';
                }
            }
          ?>
          </tbody>
        </table>
    </div>
</div>
<?php
    if (!isset($menuItem)) {
        $menuItem = 'freetextResults';
    }
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => $menuItem));
?>
