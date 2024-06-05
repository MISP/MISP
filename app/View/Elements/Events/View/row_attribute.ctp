<?php
  $tr_class = empty($trClass) ? '' : ($trClass . ' ') ;
  if (empty($context)) {
      $context = 'event';
  }
  // If row is assigned to different event (this is possible for extended event)
  if ($event['Event']['id'] != $object['event_id']) {
      $attributeEvent = $event['extensionEvents'][$object['event_id']];
      $attributeEvent = ['Event' => $attributeEvent, 'Orgc' => $attributeEvent['Orgc']]; // fix format to match standard event format
      $mayModify = $this->Acl->canModifyEvent($attributeEvent);
  } else {
      $attributeEvent = $event;
  }

  $isNew = $object['timestamp'] > $event['Event']['publish_timestamp'];
  
  $editScope = $mayModify ? 'Attribute' : 'ShadowAttribute';
  if (!empty($child)) {
      if ($child === 'last' && empty($object['ShadowAttribute'])) {
          $tr_class .= ' tableHighlightBorderBottom borderBlue';
      } else {
          $tr_class .= ' tableHighlightBorderCenter borderBlue';
      }
      if (!empty($object['ShadowAttribute'])) {
          $tr_class .= ' tableInsetOrangeFirst';
      }
  } else {
      $child = false;
      if (!empty($object['ShadowAttribute'])) {
          $tr_class .= ' tableHighlightBorderTop borderOrange';
      }
  }
  if (!empty($object['deleted'])) {
      $tr_class .= ' deleted-attribute';
  }
  if (!empty($k)) {
      $tr_class .= ' row_' . h($k);
  }

  $objectId = (int) $object['id'];

  $isNonCorrelatingType = in_array($object['type'], Attribute::NON_CORRELATING_TYPES, true);
  $correlationDisabled = $object['disable_correlation'] || $isNonCorrelatingType;
  $correlationButtonEnabled = $mayChangeCorrelation &&
      empty($event['Event']['disable_correlation']) &&
      !$isNonCorrelatingType;

  $quickEdit = function($fieldName) use ($mayModify, $object) {
      if (!$mayModify) {
          return ''; // currently it is not supported to create proposals trough quick edit
      }
      if ($object['deleted']) {
          return ''; // deleted attributes are not editable
      }
      if (($fieldName === 'value' || $fieldName === 'type') && ($object['type'] === 'attachment' || $object['type'] === 'malware-sample')) {
          return '';
      }
      return " data-edit-field=\"$fieldName\"";
  }

  ?>
  <tr id="Attribute_<?= $objectId ?>_tr" data-primary-id="<?= $objectId ?>" class="<?php echo $tr_class; ?>" tabindex="0">
      <?php if (($mayModify || !empty($extended)) && empty($disable_multi_select)): ?>
        <td style="width:10px">
        <?php if ($mayModify):?>
            <input class="select_attribute" type="checkbox" data-id="<?= $objectId ?>" aria-label="<?php echo __('Select attribute');?>">
        <?php endif; ?>
        </td>
      <?php endif; ?>
      <td class="short context hidden"><?= $objectId ?></td>
      <td class="short context hidden uuid">
        <span class="quickSelect"><?php echo h($object['uuid']); ?></span>
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
              'object_type' => 'Attribute',
              'notes' => $notes,
              'opinions' => $opinions,
              'relationships' => $relationships,
              'relationshipsInbound' => $relationshipsInbound,
          ]);
        ?>
      </td>
      <?php
        if (!empty($extended)):
      ?>
        <td class="short">
          <?php
              $event_info = sprintf('title="%s%s"',
                  __('Event info') . ':&#10;     ',
                  h($attributeEvent['Event']['info'])
              );
          ?>
          <?php echo '<a href="' . $baseurl . '/events/view/' . h($object['event_id']) . '" ' . $event_info . '>' . h($object['event_id']) . '</a>'; ?>
        </td>
      <?php
        endif;
      ?>
      <?php if ($includeOrgColumn): ?>
      <td class="short">
        <?php
          if (!empty($extended)):
              echo $this->OrgImg->getOrgLogo($attributeEvent['Orgc'], 24);
          endif;
        ?>
      </td>
      <?php endif; ?>
      <td class="short"<?= $quickEdit('category') ?>>
        <div class="inline-field-solid">
          <?php echo h($object['category']); ?>
        </div>
      </td>
      <td class="short"<?= $quickEdit('type') ?>>
        <?php if (!empty($object['object_relation'])):?>
            <div class="bold"><?php echo h($object['object_relation']); ?>:</div>
        <?php endif; ?>
        <div class="inline-field-solid">
          <?php echo h($object['type']); ?>
        </div>
      </td>
      <td id="Attribute_<?= $objectId ?>_container" class="showspaces limitedWidth shortish"<?= $quickEdit('value') ?>>
        <div class="inline-field-solid">
          <?php
              $value = $this->element('/Events/View/value_field', array('object' => $object));
              if (Configure::read('Plugin.Enrichment_hover_enable') && isset($modules) && isset($modules['hover_type'][$object['type']])) {
                  $commonDataFields = sprintf('data-object-type="attributes" data-object-id="%s"', $objectId);
                  $spanExtra = Configure::read('Plugin.Enrichment_hover_popover_only') ? '' : sprintf(' class="eventViewAttributeHover" %s', $commonDataFields);
                  $popupButton = sprintf('<i class="fa fa-search-plus useCursorPointer eventViewAttributePopup noPrint" role="button" tabindex="0" title="%s" %s></i>', __('Show hover enrichment'), $commonDataFields);
                  echo sprintf(
                      '<span%s>%s</span> %s',
                      $spanExtra,
                      $value,
                      $popupButton
                  );
              } else {
                  echo $value;
              }
          ?>
        </div>
      </td>
      <td class="short">
        <div class="attributeTagContainer">
          <?php echo $this->element('ajaxTags', array(
              'attributeId' => $objectId,
              'tags' => $object['AttributeTag'],
              'tagAccess' => $mayModify,
              'localTagAccess' => $this->Acl->canModifyTag($attributeEvent, true),
              'context' => $context,
              'scope' => 'attribute',
              'tagConflicts' => $object['tagConflicts'] ?? [],
            )
          ); ?>
        </div>
      </td>
      <?php
          if (!empty($includeRelatedTags)) {
              $element = '';
              if (!empty($object['RelatedTags'])) {
                  $element = $this->element('ajaxAttributeTags', array('attributeId' => $objectId, 'attributeTags' => $object['RelatedTags'], 'tagAccess' => false));
              }
              echo sprintf(
                  '<td class="shortish"><div %s>%s</div></td>',
                  'class="attributeRelatedTagContainer" id="#Attribute_' . $objectId . 'Related_tr .attributeTagContainer"',
                  $element
              );
          }
      ?>
      <td class="short" id="attribute_<?= $objectId ?>_galaxy">
        <?php
          echo $this->element('galaxyQuickViewNew', array(
            'data' => !empty($object['Galaxy']) ? $object['Galaxy'] : array(),
            'event' => $attributeEvent,
            'target_id' => $objectId,
            'target_type' => 'attribute',
          ));
        ?>
      </td>
      <td class="showspaces bitwider"<?= $quickEdit('comment') ?>>
        <div class="inline-field-solid">
          <?php echo nl2br(h($object['comment']), false); ?>
        </div>
      </td>
      <td class="short" style="padding-top:3px;">
        <input
          id="correlation_toggle_<?= $objectId ?>"
          class="correlation-toggle"
          aria-label="<?php echo __('Toggle correlation');?>"
          title="<?php echo __('Toggle correlation');?>"
          type="checkbox"
          <?php
            echo $correlationDisabled ? '' : ' checked';
            echo $correlationButtonEnabled ? '' : ' disabled';
          ?>
        >
      </td>
      <td class="shortish">
          <?php
            //if (!empty($event['RelatedAttribute'][$objectId])) {
                echo '<ul class="inline" style="margin:0">';
                echo $this->element('Events/View/attribute_correlations', array(
                    'scope' => 'Attribute',
                    'object' => $object,
                    'event' => $event,
                    'withPivot' => true,
                ));
                echo '</ul>';
            //}
          ?>
      </td>
      <?php if ($me['Role']['perm_view_feed_correlations']): ?>
        <td class="shortish">
          <ul class="inline correlations">
            <?php
                if (isset($object['Feed'])) {
                    foreach ($object['Feed'] as $feed) {
                        $relatedData = array(
                            __('Name') => h($feed['name']),
                            __('Provider') => h($feed['provider']),
                        );
                        if (isset($feed['event_uuids'])) {
                            $relatedData[__('Event UUIDs')] = implode('<br>', array_map('h', $feed['event_uuids']));
                        }
                        $popover = '';
                        $event_count = count($relatedData);
                        if ($event_count > 20) {
                                $popover = '<span class="bold black">' . __('Events') . '</span>: <span class="blue">' . __('Zounds... of events (%d)', $event_count) . '</span><br>';
                        } else {
                            foreach ($relatedData as $k => $v) {
                                $popover .= '<span class="bold black">' . h($k) . '</span>: <span class="blue">' . $v . '</span><br>';
                            }
                        }
                        if ($isSiteAdmin || $hostOrgUser) {
                            if ($feed['source_format'] === 'misp') {
                                $liContents = sprintf(
                                    '<form action="%s/feeds/previewIndex/%s" method="post" style="margin:0;line-height:auto;">%s%s</form>',
                                    $baseurl,
                                    h($feed['id']),
                                    sprintf(
                                        '<input type="hidden" name="data[Feed][eventid]" value="%s">',
                                        h(json_encode($feed['event_uuids'] ?? []))
                                    ),
                                    sprintf(
                                        '<input type="submit" class="linkButton useCursorPointer" value="%s" data-toggle="popover" data-content="%s" data-trigger="hover" style="margin-right:3px;line-height:normal;vertical-align: text-top;">',
                                        h($feed['id']),
                                        h($popover)
                                    )
                                );
                            } else {
                                $liContents = sprintf(
                                    '<a href="%s/feeds/previewIndex/%s" data-toggle="popover" data-content="%s" data-trigger="hover">%s</a>',
                                    $baseurl,
                                    h($feed['id']),
                                    h($popover),
                                    h($feed['id'])
                                );
                            }
                        } else {
                            $liContents = sprintf(
                                '<a href="#" data-toggle="popover" data-content="%s" data-trigger="hover">%s</a>',
                                h($popover),
                                h($feed['id'])
                            );
                        }
                        echo "<li>$liContents</li>";
                    }
                }
                if (isset($object['Server'])) {
                    foreach ($object['Server'] as $server) {
                        foreach ($server as $k => $v) {
                            if ($k == 'id') continue;
                            if (is_array($v)) {
                                foreach ($v as $k2 => $v2) {
                                    $v[$k2] = h($v2);
                                }
                                $v = implode('<br />', $v);
                            } else {
                                $v = h($v);
                            }
                        }
                        if (empty($server['event_uuids'])) {
                            $server['event_uuids'] = [0 => 1]; // Make sure to print the content once
                        }
                        $event_count = count($server['event_uuids']);
                        $popover = '';
                        if ($event_count > 20) {
                            $liContents = '';
                            $message = __('Zounds... of events (%d)', $event_count);
                            $url = $isSiteAdmin ? sprintf('%s/servers/previewIndex/%s', $baseurl, h($server['id'])) : '#';
                            $popover = '<span class=\'bold black\'>' . __('Event uuid') . '</span>: <span class="blue">' . $message . '</span><br />';
                            $liContents .= sprintf(
                                '<a href="%s" data-toggle="popover" data-content="%s" data-trigger="hover">%s</a>&nbsp;',
                                $url,
                                h($popover),
                                'S' . h($server['id']) . ':' . $message
                            );
                            echo "<li>$liContents</li>";
                        } else {
                            foreach ($server['event_uuids'] as $k => $event_uuid) {
                                $popover = '<span class=\'bold black\'>' . __('Event uuid') . '</span>: <span class="blue">' . h($event_uuid) . '</span><br />';
                                $liContents = '';
                                $url = $isSiteAdmin ? sprintf('%s/servers/previewEvent/%s/%s', $baseurl, h($server['id']), h($event_uuid)) : '#';
                                $liContents .= sprintf(
                                    '<a href="%s" data-toggle="popover" data-content="%s" data-trigger="hover">%s</a>&nbsp;',
                                    $url,
                                    h($popover),
                                    'S' . h($server['id']) . ':' . ($k + 1)
                                );
                                echo "<li>$liContents</li>";
                            }
                        }
                    }
                }
            ?>
          </ul>
        </td>
      <?php endif; ?>
      <td class="short">
          <input type="checkbox" class="toids-toggle" id="toids_toggle_<?= $objectId ?>" aria-label="<?= __('Toggle IDS flag') ?>" title="<?= __('Toggle IDS flag') ?>"<?= $object['to_ids'] ? ' checked' : ''; ?><?= $mayModify ? '' : ' disabled' ?>>
      </td>
      <td class="short"<?= $quickEdit('distribution') ?>>
          <div class="inline-field-solid">
              <?php
                  if ($object['distribution'] == 4):
              ?>
                  <a href="<?php echo $baseurl;?>/sharing_groups/view/<?php echo h($object['sharing_group_id']); ?>"><?php echo h($object['SharingGroup']['name']);?></a>
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
      <?php
          echo $this->element('/Events/View/sighting_field', array(
            'object' => $object,
          ));
          if (!empty($includeSightingdb)) {
              echo $this->element('/Events/View/sightingdb_field', array(
                'object' => $object,
              ));
          }
          if (!empty($includeDecayScore)): ?>
              <td class="decayingScoreField">
                    <div class="inline-field-solid">
                      <?php echo $this->element('DecayingModels/View/attribute_decay_score', array('scope' => 'object', 'object' => $object, 'uselink' => true)); ?>
                    </div>
              </td>
      <?php
          endif;
      ?>
      <td class="short action-links">
      <?php
          if ($object['deleted']):
            if ($isSiteAdmin || $mayModify):
        ?>
            <span class="fas fa-redo useCursorPointer" title="<?php echo __('Restore attribute');?>" role="button" tabindex="0" aria-label="<?php echo __('Restore attribute');?>" onclick="deleteObject('attributes', 'restore', '<?= $objectId ?>')"></span>
            <span class="fa fa-trash useCursorPointer" title="<?php echo __('Permanently delete attribute');?>" role="button" tabindex="0" aria-label="<?php echo __('Permanently delete attribute');?>" onclick="deleteObject('attributes', 'delete', '<?= $objectId . '/true'; ?>')"></span>
        <?php
            endif;
          else:
            if ($isAclAdd && ($isSiteAdmin || !$mayModify)):
              if (isset($modules) && isset($modules['types'][$object['type']])):
        ?>
          <span class="fas fa-asterisk useCursorPointer" role="button" tabindex="0" aria-label="<?php echo __('Query enrichment');?>" onclick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?= $objectId ?>/0/Enrichment/ShadowAttribute');" title="<?php echo __('Propose enrichment');?>">&nbsp;</span>
        <?php
              endif;
              if (isset($cortex_modules) && isset($cortex_modules['types'][$object['type']])):
        ?>
          <span class="icon-eye-open useCursorPointer" role="button" tabindex="0" aria-label="<?php echo __('Query Cortex');?>" onclick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?= $objectId ?>/0/Enrichment/ShadowAttribute/Cortex');" title="<?php echo __('Propose enrichment through Cortex');?>"></span>
        <?php
              endif;
        ?>
              <a href="<?php echo $baseurl;?>/shadow_attributes/edit/<?= $objectId ?>" title="<?php echo __('Propose Edit');?>" aria-label="<?php echo __('Propose Edit');?>" class="fa fa-comment"></a>
              <span class="fa fa-trash useCursorPointer" title="<?php echo __('Propose Deletion');?>" role="button" tabindex="0" aria-label="Propose deletion" onclick="deleteObject('shadow_attributes', 'delete', '<?= $objectId ?>')"></span>
        <?php
              if ($isSiteAdmin):
        ?>
                <span class="verticalSeparator">&nbsp;</span>
        <?php     endif;
            endif;
            if ($isSiteAdmin || $mayModify):
              if (isset($modules) && isset($modules['types'][$object['type']])):
        ?>
          <span class="fas fa-asterisk useCursorPointer" onclick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?= $objectId ?>/0/Enrichment/Attribute');" title="<?php echo __('Add enrichment');?>" role="button" tabindex="0" aria-label="<?php echo __('Add enrichment');?>">&nbsp;</span>
        <?php
              endif;
              if (isset($cortex_modules) && isset($cortex_modules['types'][$object['type']])):
        ?>
          <span class="icon-eye-open useCursorPointer" onclick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?= $objectId ?>/0/Enrichment/Attribute/Cortex');" title="<?php echo __('Add enrichment');?>" role="button" tabindex="0" aria-label="<?php echo __('Add enrichment via Cortex');?>"></span>
        <?php
              endif;
        ?>
              <a href="<?php echo $baseurl;?>/attributes/edit/<?= $objectId ?>" title="<?php echo __('Edit');?>" aria-label="<?php echo __('Edit');?>" class="fa fa-edit"></a>
            <?php
              if (empty($event['Event']['publish_timestamp'])):
            ?>
              <span class="fa fa-trash useCursorPointer" title="<?php echo __('Permanently delete attribute');?>" role="button" tabindex="0" aria-label="<?php echo __('Permanently delete attribute');?>" onclick="deleteObject('attributes', 'delete', '<?= $objectId . '/true'; ?>')"></span>
            <?php
              else:
            ?>
              <span class="fa fa-trash useCursorPointer" title="<?php echo __('Soft-delete attribute');?>" role="button" tabindex="0" aria-label="<?php echo __('Soft-delete attribute');?>" onclick="deleteObject('attributes', 'delete', '<?= $objectId ?>')"></span>
            <?php
              endif;
            endif;
          endif;
      ?>
    </td>
  </tr>
  <?php
  if (!empty($object['ShadowAttribute'])) {
      end($object['ShadowAttribute']);
      $lastElement = key($object['ShadowAttribute']);
      foreach ($object['ShadowAttribute'] as $propKey => $proposal) {
          echo $this->element('/Events/View/row_' . $proposal['objectType'], array(
              'object' => $proposal,
              'mayModify' => $mayModify,
              'mayChangeCorrelation' => $mayChangeCorrelation,
              'fieldCount' => $fieldCount,
              'child' => $propKey == $lastElement ? 'last' : true,
              'objectContainer' => $child
          ));
      }
  }
