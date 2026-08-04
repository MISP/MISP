<?php $canModify = $this->Acl->canModifyTagCollection($item) ?>
    <tr data-row-id="<?php echo h($item['TagCollection']['id']); ?>">
        <td class="short"><?php echo h($item['TagCollection']['id']);?></td>
        <td class="short"><?php echo h($item['TagCollection']['uuid']);?></td>
        <td class="short"><?php echo h($item['TagCollection']['name']);?></td>
        <td class="shortish">
          <div class="attributeTagContainer">
            <?php
                echo $this->element(
                    'ajaxTagCollectionTags',
                    array(
                        'attributeId' => $item['TagCollection']['id'],
                        'attributeTags' => $item['TagCollectionTag'],
                        'tagAccess' => $canModify,
                        'context' => 'tagCollection',
                        'tagCollection' => $item
                    )
                );
                ?>
          </div>
        </td>
        <td class="shortish">
          <?php
            echo $this->element('galaxyQuickViewNew', array(
              'tagAccess' => $canModify,
              'localTagAccess' => false,
              'data' => $item['Galaxy'],
              'target_id' => h($item['TagCollection']['id']),
              'target_type' => 'tag_collection',
              'local_tag_off' => true,
            ));
          ?>
        </td>
        <td class="short"><i class="fa fa-<?= $item['TagCollection']['all_orgs'] ? 'check' : 'times'; ?>"></i></td>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/events/index/searchorg:" . $item['Organisation']['id'];?>'">
            <?php
                echo $this->OrgImg->getOrgImg(array('name' => $item['Organisation']['name'], 'id' => $item['Organisation']['id'], 'size' => 24));
            ?>
        </td>
        <td class="short"><?php echo empty($item['User']['email']) ? '&nbsp;' : h($item['User']['email']);?></td>
        <td><?php echo h($item['TagCollection']['description']);?></td>
        <td class="short action-links">
            <?php
                if ($canModify) {
                    echo $this->Html->link('', array('action' => 'edit', $item['TagCollection']['id']), array('class' => 'fa fa-edit', 'title' => __('Edit')));
                    echo $this->Form->postLink('', array('action' => 'delete', $item['TagCollection']['id']), array('class' => 'fa fa-trash', 'title' => __('Delete')), __('Are you sure you want to delete "%s"?', $item['TagCollection']['name']));
                }
                echo sprintf(
                    '<a href="%s/tag_collections/view/%s.json" class="fa fa-cloud-download-alt black" title="%s" aria-label="%s" download="tag_collection_%s.json"></a>',
                    $baseurl,
                    h($item['TagCollection']['id']),
                    __('Download configuration'),
                    __('Download configuration'),
                    h($item['TagCollection']['id'])
                );
            ?>
        </td>
    </tr>
