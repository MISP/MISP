<?php
    foreach ($items as $item):
?>
        <tr>
            <td class="short"><?php echo h($item['TagCollection']['id']);?>&nbsp;</td>
            <td class="short"><?php echo h($item['TagCollection']['uuid']);?>&nbsp;</td>
            <td class="short"><?php echo h($item['TagCollection']['name']);?>&nbsp;</td>
            <td class="shortish">
              <div class="attributeTagContainer" id="#Tag_Collection_<?php echo h($item['TagCollection']['id']);?>_tr .attributeTagContainer">
                <?php
                    echo $this->element(
                        'ajaxTagCollectionTags',
                        array(
                            'attributeId' => $item['TagCollection']['id'],
                            'attributeTags' => $item['TagCollectionElement'],
                            'tagAccess' => ($isSiteAdmin || $me['org_id'] == $item['TagCollection']['org_id']),
                            'context' => 'tagCollection',
                            'tagCollection' => $item
                        )
                    );
                    ?>
              </div>
            </td>
            <td class="shortish">
              <?php
                echo $this->element('galaxyQuickViewMini', array(
                  'mayModify' => true,
                  'isAclTagger' => true,
                  'data' => array(),
                  'target_id' => h($item['TagCollection']['id']),
                  'target_type' => 'tag_collection'
                ));
              ?>
            </td>
            <td><?php echo h($item['TagCollection']['description']);?>&nbsp;</td>
            <td class="short action-links">
                <?php echo $this->Html->link('', array('action' => 'edit', $item['TagCollection']['id']), array('class' => 'icon-edit', 'title' => 'Edit'));?>
                <?php echo $this->Form->postLink('', array('admin' => true, 'action' => 'delete', $item['TagCollection']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete "%s"?', $item['TagCollection']['name']));?>
            </td>
        </tr>
<?php
    endforeach;
