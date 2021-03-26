<?php
$tr_class = '';
if (empty($context)) {
    $context = 'event';
}
$linkClass = 'blue';
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

$objectId = h($object['id']);

$quickEdit = function($fieldName) use ($editScope, $object, $event) {
    if ($object['deleted']) {
        return ''; // deleted attributes are not editable
    }
    if ($editScope === 'ShadowAttribute') {
        return ''; // currently it is not supported to create proposals trough quick edit
    }
    if ($fieldName === 'value' && ($object['type'] === 'attachment' || $object['type'] === 'malware-sample')) {
        return '';
    }
    return " onmouseenter=\"quickEditHover(this, '$editScope', '{$object['id']}', '$fieldName', {$event['Event']['id']});\"";
}

?>
<tr id="Attribute_<?= $objectId ?>_tr" class="<?php echo $tr_class; ?>" tabindex="0">
  <?php
    if (($mayModify || !empty($extended)) && empty($disable_multi_select)):
  ?>
      <td style="width:10px;" data-position="<?php echo 'attribute_' . $objectId ?>">
      <?php
        if ($mayModify):
      ?>
          <input id="select_<?= $objectId ?>" class="select_attribute row_checkbox" type="checkbox" data-id="<?= $objectId ?>" aria-label="<?php echo __('Select attribute');?>" />
      <?php
        endif;
      ?>
      </td>
  <?php
    endif;
  ?>
    <td class="short context hidden">
      <?= $objectId ?>
    </td>
    <td class="short context hidden uuid quickSelect"><?php echo h($object['uuid']); ?></td>
    <td class="short context hidden">
        <?php echo $this->element('/Events/View/seen_field', array('object' => $object)); ?>
    </td>
    <td class="short">
      <?php echo date('Y-m-d', $object['timestamp']); ?>
    </td>
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
      &nbsp;
    </td>
    <td class="short"<?= $quickEdit('category') ?>>
      <div id="Attribute_<?= $objectId ?>_category_placeholder" class="inline-field-placeholder"></div>
      <div id="Attribute_<?= $objectId ?>_category_solid" class="inline-field-solid">
        <?php echo h($object['category']); ?>
      </div>
    </td>
    <td class="short"<?= $quickEdit('type') ?>>
      <?php
        if (!empty($object['object_relation'])):
      ?>
          <div class="bold"><?php echo h($object['object_relation']); ?>:</div>
      <?php
        endif;
      ?>
      <div id="Attribute_<?= $objectId ?>_type_placeholder" class="inline-field-placeholder"></div>
      <div id="Attribute_<?= $objectId ?>_type_solid" class="inline-field-solid">
        <?php echo h($object['type']); ?>
      </div>
    </td>
    <td id="Attribute_<?= $objectId ?>_container" class="showspaces limitedWidth shortish"<?= $quickEdit('value') ?>>
      <div id="Attribute_<?= $objectId ?>_value_placeholder" class="inline-field-placeholder"></div>
      <div id="Attribute_<?= $objectId ?>_value_solid" class="inline-field-solid">
        <?php
            if (Configure::read('Plugin.Enrichment_hover_enable') && isset($modules) && isset($modules['hover_type'][$object['type']])) {
                $commonDataFields = sprintf('data-object-type="Attribute" data-object-id="%s"', $objectId);
                $spanExtra = Configure::read('Plugin.Enrichment_hover_popover_only') ? '' : sprintf(' class="eventViewAttributeHover" %s', $commonDataFields);
                $popupButton = sprintf('<i class="fa fa-search-plus useCursorPointer eventViewAttributePopup noPrint" title="%s" %s></i>', __('Show hover enrichment'), $commonDataFields);
                echo sprintf(
                    '<span%s>%s</span> %s',
                    $spanExtra,
                    $this->element('/Events/View/value_field', array('object' => $object, 'linkClass' => $linkClass)),
                    $popupButton
                );
            } else {
                echo $this->element('/Events/View/value_field', array('object' => $object, 'linkClass' => $linkClass));
            }
        ?>
      </div>
    </td>
    <td class="short">
      <div class="attributeTagContainer">
        <?php echo $this->element('ajaxTags', array('attributeId' => $object['id'], 'tags' => $object['AttributeTag'], 'tagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id']), 'context' => $context, 'scope' => 'attribute', 'tagConflicts' => isset($object['tagConflicts']) ? $object['tagConflicts'] : array())); ?>
      </div>
    </td>
    <?php
        if (!empty($includeRelatedTags)) {
            $element = '';
            if (!empty($object['RelatedTags'])) {
                $element = $this->element('ajaxAttributeTags', array('attributeId' => $object['id'], 'attributeTags' => $object['RelatedTags'], 'tagAccess' => false));
            }
            echo sprintf(
                '<td class="shortish"><div %s>%s</div></td>',
                'class="attributeRelatedTagContainer" id="#Attribute_' . $objectId . 'Related_tr .attributeTagContainer"',
                $element
            );
        }
    ?>
    <?php $rowId = sprintf('attribute_%s_galaxy', h($objectId)); ?>
    <td class="short" id="<?= $rowId ?>">
      <?php
        echo $this->element('galaxyQuickViewMini', array(
          'mayModify' => $mayModify,
          'isAclTagger' => $isAclTagger,
          'data' => (!empty($object['Galaxy']) ? $object['Galaxy'] : array()),
          'target_id' => $object['id'],
          'target_type' => 'attribute',
          'rowId' => $rowId,
        ));
      ?>
    </td>
    <td class="showspaces bitwider"<?= $quickEdit('comment') ?>>
      <div id="Attribute_<?= $objectId ?>_comment_placeholder" class="inline-field-placeholder"></div>
      <div id="Attribute_<?= $objectId ?>_comment_solid" class="inline-field-solid">
        <?php echo nl2br(h($object['comment'])); ?>&nbsp;
      </div>
    </td>
    <td class="short" style="padding-top:3px;">
      <input
        id="correlation_toggle_<?= $objectId ?>"
        class="correlation-toggle"
        aria-label="<?php echo __('Toggle correlation');?>"
        title="<?php echo __('Toggle correlation');?>"
        type="checkbox"
        data-attribute-id="<?= $objectId ?>"
        <?php
          echo $object['disable_correlation'] ? '' : ' checked';
          echo ($mayChangeCorrelation && empty($event['Event']['disable_correlation'])) ? '' : ' disabled';
        ?>
      >
    </td>
    <td class="shortish">
        <?php
          if (!empty($event['RelatedAttribute'][$object['id']])) {
              echo '<ul class="inline" style="margin:0">';
              echo $this->element('Events/View/attribute_correlations', array(
                  'scope' => 'Attribute',
                  'object' => $object,
                  'event' => $event,
              ));
              echo '</ul>';
          }
        ?>
    </td>
    <td class="shortish">
      <ul class="inline" style="margin:0">
        <?php
            if (isset($object['Feed'])) {
                foreach ($object['Feed'] as $feed) {
                    $relatedData = array(
                        __('Name') => h($feed['name']),
                        __('URL') => h($feed['url']),
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
                                '<a href="%s/feeds/previewIndex/%s" style="margin-right:3px;" data-toggle="popover" data-content="%s" data-trigger="hover">%s</a>',
                                $baseurl,
                                h($feed['id']),
                                h($popover),
                                h($feed['id'])
                            );
                        }
                    } else {
                        $liContents = sprintf(
                            '<span style="margin-right:3px;">%s</span>',
                            h($feed['id'])
                        );
                    }
                    echo sprintf(
                        '<li style="padding-right: 0; padding-left:0;">%s</li>',
                        $liContents
                    );
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
                                '<span style="margin-right:3px;">%s</span>',
                                'S' . h($server['id']) . ':' . ($k + 1)
                            );
                        }
                        echo sprintf(
                            '<li style="padding-right:0; padding-left:0;">%s</li>',
                            $liContents
                        );
                    }
                }
            }
        ?>
      </ul>
    </td>
    <td class="short">
        <div id="Attribute_<?= $objectId ?>_to_ids_placeholder" class="inline-field-placeholder"></div>
        <div id="Attribute_<?= $objectId ?>_to_ids_solid" class="inline-field-solid">
            <input type="checkbox" class="toids-toggle" id="toids_toggle_<?= $objectId ?>" data-attribute-id="<?= $objectId ?>" aria-label="<?= __('Toggle IDS flag') ?>" title="<?= __('Toggle IDS flag') ?>"<?= $object['to_ids'] ? ' checked' : ''; ?><?= $mayModify ? '' : ' disabled' ?>>
        </div>
    </td>
    <td class="short"<?= $quickEdit('distribution') ?>>
        <?php
            $turnRed = '';
            if ($object['distribution'] == 0) {
                $turnRed = 'style="color:red"';
            }
        ?>
        <div id="Attribute_<?= $objectId ?>_distribution_placeholder" class="inline-field-placeholder"></div>
        <div id="Attribute_<?= $objectId ?>_distribution_solid" <?php echo $turnRed; ?> class="inline-field-solid">
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
                  <div id="Attribute_<?= $objectId ?>_score_solid" class="inline-field-solid">
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
          <span class="fas fa-redo useCursorPointer" title="<?php echo __('Restore attribute');?>" role="button" tabindex="0" aria-label="<?php echo __('Restore attribute');?>" onClick="deleteObject('attributes', 'restore', '<?= $objectId ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
          <span class="fa fa-trash useCursorPointer" title="<?php echo __('Permanently delete attribute');?>" role="button" tabindex="0" aria-label="i<?php echo __('Permanently delete attribute');?>" onClick="deleteObject('attributes', 'delete', '<?= $objectId . '/true'; ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
      <?php
          endif;
        else:
          if ($isAclAdd && ($isSiteAdmin || !$mayModify)):
            if (isset($modules) && isset($modules['types'][$object['type']])):
      ?>
        <span class="fas fa-asterisk useCursorPointer" role="button" tabindex="0" aria-label="<?php echo __('Query enrichment');?>" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?= $objectId ?>/ShadowAttribute');" title="<?php echo __('Propose enrichment');?>">&nbsp;</span>
      <?php
            endif;
            if (isset($cortex_modules) && isset($cortex_modules['types'][$object['type']])):
      ?>
        <span class="icon-eye-open useCursorPointer" title="<?php echo __('Query Cortex');?>" role="button" tabindex="0" aria-label="<?php echo __('Query Cortex');?>" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?= $objectId ?>/ShadowAttribute/Cortex');" title="<?php echo __('Propose enrichment through Cortex');?>"></span>
      <?php
            endif;
      ?>
            <a href="<?php echo $baseurl;?>/shadow_attributes/edit/<?= $objectId ?>" title="<?php echo __('Propose Edit');?>" aria-label="<?php echo __('Propose Edit');?>" class="fa fa-comment useCursorPointer"></a>
            <span class="fa fa-trash useCursorPointer" title="<?php echo __('Propose Deletion');?>" role="button" tabindex="0" aria-label="Propose deletion" onClick="deleteObject('shadow_attributes', 'delete', '<?= $objectId ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
      <?php
            if ($isSiteAdmin):
      ?>
              <span class="verticalSeparator">&nbsp;</span>
      <?php     endif;
          endif;
          if ($isSiteAdmin || $mayModify):
            if (isset($modules) && isset($modules['types'][$object['type']])):
      ?>
        <span class="fas fa-asterisk useCursorPointer" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?= $objectId ?>/Attribute');" title="<?php echo __('Add enrichment');?>" role="button" tabindex="0" aria-label="<?php echo __('Add enrichment');?>">&nbsp;</span>
      <?php
            endif;
            if (isset($cortex_modules) && isset($cortex_modules['types'][$object['type']])):
      ?>
        <span class="icon-eye-open useCursorPointer" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?= $objectId ?>/Attribute/Cortex');" title="<?php echo __('Add enrichment');?>" role="button" tabindex="0" aria-label="<?php echo __('Add enrichment via Cortex');?>"></span>
      <?php
            endif;
      ?>
            <a href="<?php echo $baseurl;?>/attributes/edit/<?= $objectId ?>" title="<?php echo __('Edit');?>" aria-label="<?php echo __('Edit');?>" class="fa fa-edit useCursorPointer"></a>
          <?php
            if (empty($event['Event']['publish_timestamp'])):
          ?>
            <span class="fa fa-trash useCursorPointer" title="<?php echo __('Permanently delete attribute');?>" role="button" tabindex="0" aria-label="i<?php echo __('Permanently delete attribute');?>" onClick="deleteObject('attributes', 'delete', '<?= $objectId . '/true'; ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
          <?php
            else:
          ?>
            <span class="fa fa-trash useCursorPointer" title="<?php echo __('Soft-delete attribute');?>" role="button" tabindex="0" aria-label="<?php echo __('Soft-delete attribute');?>" onClick="deleteObject('attributes', 'delete', '<?= $objectId ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
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
