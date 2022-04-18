<?php
$tr_class = '';
if (empty($context)) {
    $context = 'event';
}
if ($event['Event']['id'] != $object['event_id']) {
    if (!$isSiteAdmin && $event['extensionEvents'][$object['event_id']]['Orgc']['id'] != $me['org_id']) {
        $mayModify = false;
    }
}
$editScope = ($isSiteAdmin || $mayModify) ? 'Attribute' : 'ShadowAttribute';
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

$quickEdit = function($fieldName) use ($mayModify, $object) {
    if (!$mayModify) {
        return ''; // currently it is not supported to create proposals trough quick edit
    }
    if ($object['deleted']) {
        return ''; // deleted attributes are not editable
    }
    if ($fieldName === 'value' && ($object['type'] === 'attachment' || $object['type'] === 'malware-sample')) {
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
    <td class="short context hidden uuid quickSelect"><?php echo h($object['uuid']); ?></td>
    <td class="short context hidden">
        <?php echo $this->element('/Events/View/seen_field', array('object' => $object)); ?>
    </td>
    <td class="short timestamp"><?= $this->Time->date($object['timestamp']) ?></td>
    <?php
      if (!empty($extended)):
    ?>
      <td class="short">
        <?php
            $event_info = sprintf('title="%s%s"',
                __('Event info') . ':&#10;     ',
                $object['event_id'] != $event['Event']['id'] ? h($event['extensionEvents'][$object['event_id']]['info']) : h($event['Event']['info'])
            );
        ?>
        <?php echo '<a href="' . $baseurl . '/events/view/' . h($object['event_id']) . '" ' . $event_info . '>' . h($object['event_id']) . '</a>'; ?>
      </td>
    <?php
      endif;
    ?>
    <td class="short">
      <?php
        if (!empty($extended)):
          if ($object['event_id'] != $event['Event']['id']):
            $extensionOrg = $event['extensionEvents'][$object['event_id']]['Orgc'];
            echo $this->OrgImg->getOrgLogo($extensionOrg, 24);
          else:
            echo $this->OrgImg->getOrgLogo($event['Orgc'], 24);
          endif;
        endif;
      ?>
    </td>
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
                $commonDataFields = sprintf('data-object-type="Attribute" data-object-id="%s"', $objectId);
                $spanExtra = Configure::read('Plugin.Enrichment_hover_popover_only') ? '' : sprintf(' class="eventViewAttributeHover" %s', $commonDataFields);
                $popupButton = sprintf('<i class="fa fa-search-plus useCursorPointer eventViewAttributePopup noPrint" title="%s" %s></i>', __('Show hover enrichment'), $commonDataFields);
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
            'tagAccess' => ($isSiteAdmin || $mayModify),
            'localTagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id'] || (int)$me['org_id'] === Configure::read('MISP.host_org_id')),
            'context' => $context,
            'scope' => 'attribute',
            'tagConflicts' => isset($object['tagConflicts']) ? $object['tagConflicts'] : array()
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
          'mayModify' => $mayModify,
          'isAclTagger' => $isAclTagger,
          'data' => (!empty($object['Galaxy']) ? $object['Galaxy'] : array()),
          'event' => $event,
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
          echo $object['disable_correlation'] ? '' : ' checked';
          echo ($mayChangeCorrelation && empty($event['Event']['disable_correlation'])) ? '' : ' disabled';
        ?>
      >
    </td>
    <td class="shortish">
        <?php
          if (!empty($event['RelatedAttribute'][$objectId])) {
              echo '<ul class="inline" style="margin:0">';
              echo $this->element('Events/View/attribute_correlations', array(
                  'scope' => 'Attribute',
                  'object' => $object,
                  'event' => $event,
                  'withPivot' => true,
              ));
              echo '</ul>';
          }
        ?>
    </td>
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
                    foreach ($relatedData as $k => $v) {
                        $popover .= '<span class="bold black">' . $k . '</span>: <span class="blue">' . $v . '</span><br>';
                    }
                    if ($isSiteAdmin || $hostOrgUser) {
                        if ($feed['source_format'] === 'misp') {
                            $liContents = sprintf(
                                '<form action="%s/feeds/previewIndex/%s" method="post" style="margin:0;line-height:auto;">%s%s</form>',
                                $baseurl,
                                h($feed['id']),
                                sprintf(
                                    '<input type="hidden" name="data[Feed][eventid]" value="%s">',
                                    h(json_encode($feed['event_uuids']))
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
                            '<span>%s</span>',
                            h($feed['id'])
                        );
                    }
                    echo "<li>$liContents</li>";
                }
            }
            if (isset($object['Server'])) {
                foreach ($object['Server'] as $server) {
                    $popover = '';
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
                        $popover .= '<span class=\'bold black\'>' . Inflector::humanize(h($k)) . '</span>: <span class="blue">' . $v . '</span><br />';
                    }
                    foreach ($server['event_uuids'] as $k => $event_uuid) {
                        $liContents = '';
                        if ($isSiteAdmin) {
                            $liContents .= sprintf(
                                '<a href="%s/servers/previewEvent/%s/%s" data-toggle="popover" data-content="%s" data-trigger="hover">%s</a>&nbsp;',
                                $baseurl,
                                h($server['id']),
                                h($event_uuid),
                                h($popover),
                                'S' . h($server['id']) . ':' . ($k + 1)
                            );
                        } else {
                            $liContents .= sprintf(
                                '<span>%s</span>',
                                'S' . h($server['id']) . ':' . ($k + 1)
                            );
                        }
                        echo "<li>$liContents</li>";
                    }
                }
            }
        ?>
      </ul>
    </td>
    <td class="short">
        <input type="checkbox" class="toids-toggle" id="toids_toggle_<?= $objectId ?>" aria-label="<?= __('Toggle IDS flag') ?>" title="<?= __('Toggle IDS flag') ?>"<?= $object['to_ids'] ? ' checked' : ''; ?><?= $mayModify ? '' : ' disabled' ?>>
    </td>
    <td class="short"<?= $quickEdit('distribution') ?>>
        <div class="inline-field-solid<?= $object['distribution'] == 0 ? ' red' : '' ?>">
            <?php
                if ($object['distribution'] == 4):
            ?>
                <a href="<?php echo $baseurl;?>/sharing_groups/view/<?php echo h($object['sharing_group_id']); ?>"><?php echo h($object['SharingGroup']['name']);?></a>
            <?php
                else:
                    echo h($shortDist[$object['distribution']]);
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
        <span class="fas fa-asterisk useCursorPointer" role="button" tabindex="0" aria-label="<?php echo __('Query enrichment');?>" onclick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?= $objectId ?>/ShadowAttribute');" title="<?php echo __('Propose enrichment');?>">&nbsp;</span>
      <?php
            endif;
            if (isset($cortex_modules) && isset($cortex_modules['types'][$object['type']])):
      ?>
        <span class="icon-eye-open useCursorPointer" role="button" tabindex="0" aria-label="<?php echo __('Query Cortex');?>" onclick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?= $objectId ?>/ShadowAttribute/Cortex');" title="<?php echo __('Propose enrichment through Cortex');?>"></span>
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
        <span class="fas fa-asterisk useCursorPointer" onclick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?= $objectId ?>/Attribute');" title="<?php echo __('Add enrichment');?>" role="button" tabindex="0" aria-label="<?php echo __('Add enrichment');?>">&nbsp;</span>
      <?php
            endif;
            if (isset($cortex_modules) && isset($cortex_modules['types'][$object['type']])):
      ?>
        <span class="icon-eye-open useCursorPointer" onclick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?= $objectId ?>/Attribute/Cortex');" title="<?php echo __('Add enrichment');?>" role="button" tabindex="0" aria-label="<?php echo __('Add enrichment via Cortex');?>"></span>
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
