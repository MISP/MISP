<?php
  $tr_class = 'tableHighlightBorderTop borderBlue';
  if ($event['Event']['id'] != $object['event_id']) {
      $objectEvent = $event['extensionEvents'][$object['event_id']];
      $objectEvent = ['Event' => $objectEvent, 'Orgc' => $objectEvent['Orgc']]; // fix format to match standard event format
      $mayModify = $this->Acl->canMofiyEvent($objectEvent);
  } else {
      $objectEvent = $event;
  }
  $attributeInObjectCollapsed = is_null(Configure::read('MISP.collapse_attribute_in_object')) ? false : !empty(Configure::read('MISP.collapse_attribute_in_object'));
  $isNew = $object['timestamp'] > $event['Event']['publish_timestamp'];
  if ($object['deleted']) $tr_class .= ' lightBlueRow';
  else $tr_class .= ' blueRow';
  if (!empty($k)) {
    $tr_class .= ' row_' . h($k);
  }
$quickEdit = function($fieldName) use ($mayModify) {
    if (!$mayModify) {
        return ''; // without permission it is not possible to edit object
    }
    return " data-edit-field=\"$fieldName\"";
};
$objectId = intval($object['id']);
?>
<tr id="Object_<?= $objectId ?>_tr" data-primary-id="<?= $objectId ?>" class="<?php echo $tr_class; ?>" tabindex="0" data-uuid="<?= h($object['uuid']) ?>">
  <?php
    if ($mayModify || $extended):
  ?>
    <td style="width:10px;"></td>
  <?php
    endif;
  ?>
  <td class="short context hidden"><?= $objectId ?></td>
  <td class="short context hidden uuid">
        <span class="quickSelect"><?php echo h($object['uuid']); ?></span>
        <?php
          $notes = !empty($object['Note']) ? $object['Note'] : [];
          $opinions = !empty($object['Opinion']) ? $object['Opinion'] : [];
          $relationships = !empty($object['Relationship']) ? $object['Relationship'] : [];
          $relationshipsInbound = !empty($object['RelationshipInbound']) ? $object['RelationshipInbound'] : [];
          echo $this->element('genericElements/Analyst_data/generic_simple', [
              'analyst_data' => ['notes' => $notes, 'opinions' => $opinions, 'relationships_outbound' => $relationships, 'relationships_inbound' => $relationshipsInbound],
              'object_uuid' => $object['uuid'],
              'object_type' => 'Attribute'
          ]);
        ?>
      </td>
  <td class="short context hidden">
      <?php echo $this->element('/Events/View/seen_field', array('object' => $object)); ?>
  </td>
  <td class="short timestamp <?= $isNew ? 'bold red' : '' ?>" <?= $isNew ? 'title="' . __('Element or modification to an existing element has not been published yet.') . '"' : '' ?>><?= $this->Time->date($object['timestamp']) . ($isNew ? '*' : '') ?></td>
  <td class="short context">
      <?php
        $notes = !empty($object['Note']) ? $object['Note'] : [];
        $opinions = !empty($object['Opinion']) ? $object['Opinion'] : [];
        $relationships = !empty($object['Relationship']) ? $object['Relationship'] : [];
        $relationshipsInbound = !empty($object['RelationshipInbound']) ? $object['RelationshipInbound'] : [];
        echo $this->element('genericElements/shortUuidWithNotesAjax', [
            'uuid' => $object['uuid'],
            'object_type' => 'Object',
            'notes' => $notes,
            'opinions' => $opinions,
            'relationships' => $relationships,
            'relationshipsInbound' => $relationshipsInbound,
        ]);
      ?>
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
  <?php if ($includeOrgColumn): ?>
  <td class="short">
    <?php
      if ($extended):
          echo $this->OrgImg->getOrgImg(array('name' => $objectEvent['Orgc']['name'], 'id' => $objectEvent['Orgc']['id'], 'size' => 24));
      endif;
    ?>
  </td>
  <?php endif; ?>
  <td colspan="<?= $includeRelatedTags ? 6 : 5 ?>">
    <div style="display: flex">
      <div style="width: 25%;">
        <span class="bold"><?php echo __('Object name: ');?></span>
        <span style="white-space: nowrap;">
          <?php echo h($object['name']);?>
          <span class="fa fa-expand useCursorPointer" title="<?php echo __('Expand or Collapse');?>" role="button" tabindex="0" aria-label="<?php echo __('Expand or Collapse');?>" data-toggle="collapse" data-target="#Object_<?php echo $objectId ?>_collapsible"></span>
        </span>
        <br>
        <div id="Object_<?= $objectId ?>_collapsible" class="collapse">
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
      </div>
      <div style="margin-left: 2em; flex-grow: 1;">
          <?php if (!empty($object['Attribute'])): ?>
            <?php
              $firstAttr = $object['Attribute'][0]; // Attributes are already ordered based on their UI priority
            ?>
            <span style="border: 1px solid #2f5a93; background-color: #5184c8; border-radius: 5px 5px 0 0; padding: 2px 4px; margin-left: -1px;">
              <strong><?= h($firstAttr['object_relation']) ?></strong> :: <span><?= h($firstAttr['type']) ?></span>
            </span>
            <span><pre style="margin-bottom: 0; padding: 0.25em 0.5em; border-radius: 0 5px 5px 5px;"><?= h($firstAttr['value']) ?></pre></span>
            <div style="margin-top: 0.25em;">
              <button class="btn btn-mini btn-primary <?= $attributeInObjectCollapsed ? 'content-hidden' : '' ?>" title="<?php echo __('Toggle Attributes visibility');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle Attributes visibility');?>" data-toggle="quickcollapse" data-target=".Object_<?php echo $objectId ?>_collapsible_attr">
                <span class="fa fa-angle-double-<?= $attributeInObjectCollapsed ? 'down' : 'up' ?>" data-text-show="fa-angle-double-down" data-class-hide="fa-angle-double-up"></span>
                <span class="text" data-text-hide="<?php echo __n('Hide the Attribute', 'Hide %s Attributes', count($object['Attribute']), count($object['Attribute']));?>" data-text-show="<?php echo __n('Show 1 Attribute', 'Show %s Attributes', count($object['Attribute']), count($object['Attribute']));?>">
                  <?php echo $attributeInObjectCollapsed ? __n('Show 1 Attribute', 'Show %s Attributes', count($object['Attribute']), count($object['Attribute'])) : __n('Hide the Attribute', 'Hide %s Attributes', count($object['Attribute']), count($object['Attribute']));?>
                </span>
              </button>
            </div>
          <?php endif; ?>
      </div>
    </div>
  </td>
  <td class="showspaces bitwider"<?= $quickEdit('comment') ?>>
    <div class="inline-field-solid">
      <?= nl2br(h($object['comment']), false); ?>
    </div>
  </td>
  <td colspan="<?= $me['Role']['perm_view_feed_correlations'] ? 4 : 3 ?>"></td>
  <td class="shortish"<?= $quickEdit('distribution') ?>>
    <div class="inline-field-solid">
      <?php
          if ($object['distribution'] == 4):
      ?>
        <a href="<?php echo $baseurl; ?>/sharing_groups/view/<?php echo h($object['sharing_group_id']); ?>"><?php echo h($object['SharingGroup']['name']);?></a>
      <?php
          else:
              if ($object['distribution'] == 0) {
                  echo '<span class="red">' . h($shortDist[$object['distribution']]) . '</span>';
              } else {
                  echo h($shortDist[$object['distribution']]);
              }
          endif;
      ?>
    </div>
  </td>
  <td colspan="2"></td>
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
          if (Configure::read('Plugin.Enrichment_services_enable') && ($isSiteAdmin || $mayModify) && (isset($modules) && isset($modules['types'][$object['name']]))) {
            echo sprintf(
              '<span class="fa fa-asterisk white useCursorPointer" title="%1$s" role="button" tabindex="0" aria-label="%1$s" onclick="%2$s"></span> ',
              __('Add enrichment'),
              sprintf(
                'simplePopup(\'%s/events/queryEnrichment/%s/0/Enrichment/Object\');',
                  $baseurl, $objectId
              )
            );
          }

          if (empty($object['deleted'])) {
            echo sprintf(
              '<a href="%s/objects/edit/%s" title="%s" aria-label="%s" class="fa fa-edit white"></a> ',
              $baseurl,
                $objectId,
              __('Edit'),
              __('Edit')
            );
            echo sprintf(
              '<span class="fa fa-trash white useCursorPointer" title="%1$s" role="button" tabindex="0" aria-label="%1$s" onclick="%2$s"></span>',
              (empty($event['Event']['publish_timestamp']) ? __('Permanently delete object') : __('Soft delete object')),
              sprintf(
                'deleteObject(\'objects\', \'delete\', \'%s\');',
                empty($event['Event']['publish_timestamp']) ? $objectId . '/true' : $objectId
              )
            );
        } else {
            echo sprintf(
              '<span class="fa fa-trash white useCursorPointer" title="%1$s" role="button" tabindex="0" aria-label="%1$s" onclick="%2$s"></span>',
              __('Permanently delete object'),
              sprintf(
                'deleteObject(\'objects\', \'delete\', \'%s\');',
                  $objectId . '/true'
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
            'trClass' => ($attributeInObjectCollapsed ? 'd-none ' : '') . sprintf('Object_%s_collapsible_attr', $objectId),
            'object' => $attribute,
            'mayModify' => $mayModify,
            'mayChangeCorrelation' => $mayChangeCorrelation,
            'fieldCount' => $fieldCount,
            'child' => $attrKey === $lastElement ? 'last' : true,
        ));
    }
    ?>
    <?php
    if ($mayModify) {
        echo '<tr class="objectAddFieldTr"><td><span class="fa fa-plus-circle objectAddField" title="' . __('Add an Object Attribute') . '" data-popover-popup="' . $baseurl . '/objects/quickFetchTemplateWithValidObjectAttributes/' . $objectId . '"></span></td></tr>';
    }
  }
  ?>
</div>
