<?php
  $linkClass = 'white';
  $currentType = 'Object';
  $tr_class = 'tableHighlightBorderTop borderBlue';
  if ($event['Event']['id'] != $object['event_id']) {
    if (!$isSiteAdmin && $event['extensionEvents'][$object['event_id']]['Orgc']['id'] != $me['org_id']) {
      $mayModify = false;
    }
  }
  if ($object['deleted']) $tr_class .= ' lightBlueRow';
  else $tr_class .= ' blueRow';
  if (!empty($k)) {
    $tr_class .= ' row_' . h($k);
  }
?>
<tr id="Object_<?php echo $object['id']; ?>_tr" class="<?php echo $tr_class; ?>" tabindex="0">
  <?php
    if ($mayModify || $extended):
  ?>
    <td style="width:10px;"></td>
  <?php
    endif;
  ?>
  <td class="short context hidden">
    <?php echo h($object['id']); ?>
  </td>
  <td class="short context hidden uuid quickSelect"><?php echo h($object['uuid']); ?></td>
  <td class="short context hidden">
      <?php echo $this->element('/Events/View/seen_field', array('object' => $object)); ?>
  </td>
  <td class="short">
    <?php echo date('Y-m-d', $object['timestamp']); ?>
  </td>
  <?php
    if ($extended):
  ?>
    <td class="short">
      <?php echo '<a href="' . $baseurl . '/events/view/' . h($object['event_id']) . '" class="white">' . h($object['event_id']) . '</a>'; ?>
    </td>
  <?php
    endif;
  ?>
  <td class="short">
    <?php
      if ($extended):
        if ($object['event_id'] != $event['Event']['id']):
          $extensionOrg = $event['extensionEvents'][$object['event_id']]['Orgc'];
          echo $this->OrgImg->getOrgImg(array('name' => $extensionOrg['name'], 'id' => $extensionOrg['id'], 'size' => 24));
        else:
          echo $this->OrgImg->getOrgImg(array('name' => $event['Orgc']['name'], 'id' => $event['Orgc']['id'], 'size' => 24));
        endif;
      endif;
    ?>
    &nbsp;
  </td>
  <td colspan="<?= $includeRelatedTags ? 6 : 5 ?>">
    <span class="bold"><?php echo __('Object name: ');?></span><?php echo h($object['name']);?>
    <span class="fa fa-expand useCursorPointer" title="<?php echo __('Expand or Collapse');?>" role="button" tabindex="0" aria-label="<?php echo __('Expand or Collapse');?>" data-toggle="collapse" data-target="#Object_<?php echo h($object['id']); ?>_collapsible"></span>
    <br />
    <div id="Object_<?php echo $object['id']; ?>_collapsible" class="collapse">
        <span class="bold"><?php echo __('UUID');?>: </span><?php echo h($object['uuid']);?><br />
        <span class="bold"><?php echo __('Meta-category: ');?></span><?php echo h($object['meta-category']);?><br />
        <span class="bold"><?php echo __('Description: ');?></span><?php echo h($object['description']);?><br />
        <span class="bold"><?php echo __('Template: ');?></span><?php echo h($object['name']) . ' v' . h($object['template_version']) . ' (' . h($object['template_uuid']) . ')'; ?>
    </div>
    <?php
      echo $this->element('/Events/View/row_object_reference', array(
        'deleted' => $deleted,
        'object' => $object,
        'mayModify' => $mayModify
      ));
      if (!empty($object['referenced_by'])) {
        echo $this->element('/Events/View/row_object_referenced_by', array(
          'deleted' => $deleted,
          'object' => $object
        ));
      }
    ?>
  </td>
  <td class="showspaces bitwider" onmouseenter="quickEditHover(this, 'Object', '<?php echo $object['id']; ?>', 'comment', <?php echo $event['Event']['id'];?>);">
    <div id="Object_<?php echo $object['id']; ?>_comment_placeholder" class="inline-field-placeholder"></div>
    <div id="Object_<?php echo $object['id']; ?>_comment_solid" class="inline-field-solid">
      <?php echo nl2br(h($object['comment'])); ?>&nbsp;
    </div>
  </td>
  <td colspan="4">&nbsp;
  </td>
  <td class="shortish" onmouseenter="quickEditHover(this, 'Object', '<?php echo $object['id']; ?>', 'distribution', <?php echo $event['Event']['id'];?>);">
    <?php
      $turnRed = '';
      if ($object['distribution'] == 0) $turnRed = 'style="color:red"';
    ?>
    <div id="<?php echo $currentType . '_' . $object['id'] . '_distribution_placeholder'; ?>" class="inline-field-placeholder"></div>
    <div id="<?php echo $currentType . '_' . $object['id'] . '_distribution_solid'; ?>" <?php echo $turnRed; ?> class="inline-field-solid">
      <?php
          if ($object['distribution'] == 4):
      ?>
        <a href="<?php echo $baseurl; ?>/sharing_groups/view/<?php echo h($object['sharing_group_id']); ?>"><?php echo h($object['SharingGroup']['name']);?></a>
      <?php
          else:
            echo h($shortDist[$object['distribution']]);
          endif;
      ?>&nbsp;
    </div>
  </td>
  <td>&nbsp;</td>
  <td>&nbsp;</td>
  <?php
    $paddedFields = array('includeSightingdb', 'includeDecayScore');
    foreach ($paddedFields as $paddedField) {
        if (!empty(${$paddedField})) {
            echo '<td>&nbsp;</td>';
        }
    }
  ?>
  <td class="short action-links">
    <?php
      if ($mayModify) {
          if (empty($object['deleted'])) {
            echo sprintf(
              '<a href="%s/objects/edit/%s" title="%s" aria-label="%s" class="fa fa-edit white useCursorPointer"></a> ',
              $baseurl,
              h($object['id']),
              __('Edit'),
              __('Edit')
            );
            echo sprintf(
              '<span class="fa fa-trash white useCursorPointer" title="%1$s" role="button" tabindex="0" aria-label="%1$s" onClick="%2$s"></span>',
              (empty($event['Event']['publish_timestamp']) ? __('Permanently delete object') : __('Soft delete object')),
              sprintf(
                'deleteObject(\'objects\', \'delete\', \'%s\', \'%s\');',
                empty($event['Event']['publish_timestamp']) ? h($object['id']) . '/true' : h($object['id']),
                h($event['Event']['id'])
              )
            );
        } else {
            echo sprintf(
              '<span class="fa fa-trash white useCursorPointer" title="%1$s" role="button" tabindex="0" aria-label="%1$s" onClick="%2$s"></span>',
              __('Permanently delete object'),
              sprintf(
                'deleteObject(\'objects\', \'delete\', \'%s\', \'%s\');',
                h($object['id']) . '/true',
                h($event['Event']['id'])
              )
            );
        }
      }
    ?>
  </td>
</tr>
<?php
  if (!empty($object['Attribute'])) {
    end($object['Attribute']);
    $lastElement = key($object['Attribute']);
    foreach ($object['Attribute'] as $attrKey => $attribute) {
      echo $this->element('/Events/View/row_' . $attribute['objectType'], array(
        'object' => $attribute,
        'mayModify' => $mayModify,
        'mayChangeCorrelation' => $mayChangeCorrelation,
        'fieldCount' => $fieldCount,
        'child' => $attrKey == $lastElement ? 'last' : true
      ));
    }
    echo '<tr class="objectAddFieldTr"><td><span class="fa fa-plus-circle objectAddField" title="' . __('Add an Object Attribute') .'" onclick="popoverPopup(this, ' . h($object['id']) . ', \'objects\', \'quickFetchTemplateWithValidObjectAttributes\')"></span></td></tr>';
  }
