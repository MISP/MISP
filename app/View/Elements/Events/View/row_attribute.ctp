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
?>
<tr id = "Attribute_<?php echo h($object['id']); ?>_tr" class="<?php echo $tr_class; ?>" tabindex="0">
  <?php
    if (($mayModify || !empty($extended)) && empty($disable_multi_select)):
  ?>
      <td style="width:10px;" data-position="<?php echo 'attribute_' . h($object['id']); ?>">
      <?php
        if ($mayModify):
      ?>
          <input id = "select_<?php echo $object['id']; ?>" class="select_attribute row_checkbox" type="checkbox" data-id="<?php echo $object['id'];?>" aria-label="<?php echo __('Select attribute');?>" />
      <?php
        endif;
      ?>
      </td>
  <?php
    endif;
  ?>
    <td class="short context hidden">
      <?php echo h($object['id']); ?>
    </td>
    <td class="short context hidden">
      <?php echo h($object['uuid']); ?>
    </td>
    <td class="short">
      <?php echo date('Y-m-d', $object['timestamp']); ?>
    </td>
    <?php
      if (!empty($extended)):
    ?>
      <td class="short">
        <?php
            $event_info = '';
            if (!empty($extended)) {
                $event_info = sprintf('title="%s%s"',
                    __('Event info') . ':&#10;     ',
                    $object['event_id'] != $event['Event']['id'] ? h($event['extensionEvents'][$object['event_id']]['info']) : h($event['Event']['info'])
                );
            }
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
            echo $this->OrgImg->getOrgImg(array('name' => $extensionOrg['name'], 'id' => $extensionOrg['id'], 'size' => 24));
          else:
            echo $this->OrgImg->getOrgImg(array('name' => $event['Orgc']['name'], 'id' => $event['Orgc']['id'], 'size' => 24));
          endif;
        endif;
      ?>
      &nbsp;
    </td>
    <td class="short" onmouseenter="quickEditHover(this, '<?php echo $editScope; ?>', '<?php echo $object['id']; ?>', 'category', <?php echo $event['Event']['id'];?>);">
      <div id = "Attribute_<?php echo $object['id']; ?>_category_placeholder" class = "inline-field-placeholder"></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_category_solid" class="inline-field-solid">
        <?php echo h($object['category']); ?>
      </div>
    </td>
    <td class="short" onmouseenter="quickEditHover(this, '<?php echo $editScope; ?>', '<?php echo $object['id']; ?>', 'type', <?php echo $event['Event']['id'];?>);">
      <?php
        if (!empty($object['object_relation'])):
      ?>
          <div class="bold"><?php echo h($object['object_relation']); ?>:</div>
      <?php
        endif;
      ?>
      <div></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_type_placeholder" class = "inline-field-placeholder"></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_type_solid" class="inline-field-solid">
        <?php echo h($object['type']); ?>
      </div>
    </td>
    <?php
        if ('attachment' !== $object['type'] && 'malware-sample' !== $object['type']):
            $editable = ' onmouseenter="quickEditHover(this, \'' . $editScope . '\', \'' . $object['id'] . '\', \'value\', \'' . $event['Event']['id'] . '\' );"';
        else:
            $editable = '';
        endif;
    ?>
    <td id="Attribute_<?php echo h($object['id']); ?>_container" class="showspaces limitedWidth shortish" <?php echo $editable; ?>>
    <div id="Attribute_<?php echo $object['id']; ?>_value_placeholder" class="inline-field-placeholder"></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_value_solid" class="inline-field-solid">
        <span>
        <?php
            $spanExtra = '';
            $popupButton = '';
            if (Configure::read('Plugin.Enrichment_hover_enable') && isset($modules) && isset($modules['hover_type'][$object['type']])) {
                $commonDataFields = sprintf(
                    'data-object-type="%s" data-object-id="%s"',
                    "Attribute",
                    h($object['id'])
                );
                $spanExtra = sprintf(' class="eventViewAttributeHover" %s', $commonDataFields);
                $popupButton = sprintf('<i class="fa fa-search-plus useCursorPointer eventViewAttributePopup" %s></i>', $commonDataFields);
            }
            echo sprintf(
                '<span%s style="white-space: pre-wrap;">%s</span> %s',
                $spanExtra,
                $this->element('/Events/View/value_field', array('object' => $object, 'linkClass' => $linkClass)),
                $popupButton
            );
        ?>
        </span>
        <?php
          if (isset($object['warnings'])) {
            $temp = '';
            $components = array(1 => 0, 2 => 1);
            $valueParts = explode('|', $object['value']);
            foreach ($components as $component => $valuePart) {
              if (isset($object['warnings'][$component]) && isset($valueParts[$valuePart])) {
                foreach ($object['warnings'][$component] as $warning) $temp .= '<span class=\'bold\'>' . h($valueParts[$valuePart]) . '</span>: <span class=\'red\'>' . h($warning) . '</span><br />';
              }
            }
            echo ' <span aria-label="' . __('warning') . '" role="img" tabindex="0" class="fa fa-exclamation-triangle" data-placement="right" data-toggle="popover" data-content="' . h($temp) . '" data-trigger="hover" data-placement="right">&nbsp;</span>';
          }
        ?>
      </div>
    </td>
    <td class="short">
      <div class="attributeTagContainer" id="#Attribute_<?php echo h($object['id']);?>_tr .attributeTagContainer">
        <?php echo $this->element('ajaxTags', array('attributeId' => $object['id'], 'tags' => $object['AttributeTag'], 'tagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id']), 'context' => $context, 'scope' => 'attribute')); ?>
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
                'class="attributeRelatedTagContainer" id="#Attribute_' . h($object['id']) . 'Related_tr .attributeTagContainer"',
                $element
            );
        }
    ?>
    <td class="short" id="attribute_<?php echo h($object['id']); ?>_galaxy">
      <?php
        echo $this->element('galaxyQuickViewMini', array(
          'mayModify' => $mayModify,
          'isAclTagger' => $isAclTagger,
          'data' => (!empty($object['Galaxy']) ? $object['Galaxy'] : array()),
          'target_id' => $object['id'],
          'target_type' => 'attribute'
        ));
      ?>
    </td>
    <td class="showspaces bitwider" onmouseenter="quickEditHover(this, '<?php echo $editScope; ?>', '<?php echo $object['id']; ?>', 'comment', <?php echo $event['Event']['id'];?>);">
      <div id = "Attribute_<?php echo $object['id']; ?>_comment_placeholder" class = "inline-field-placeholder"></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_comment_solid" class="inline-field-solid">
        <?php echo nl2br(h($object['comment'])); ?>&nbsp;
      </div>
    </td>
    <td class="short" style="padding-top:3px;">
      <input
        id="correlation_toggle_<?php echo h($object['id']); ?>"
        class="correlation-toggle"
        aria-label="<?php echo __('Toggle correlation');?>"
        title="<?php echo __('Toggle correlation');?>"
        type="checkbox"
        data-attribute-id="<?php echo h($object['id']); ?>"
        <?php
          echo $object['disable_correlation'] ? '' : ' checked';
          echo ($mayChangeCorrelation && empty($event['Event']['disable_correlation'])) ? '' : ' disabled';
        ?>
      >
    </td>
    <td class="shortish">
      <ul class="inline" style="margin:0px;">
        <?php
          if (!empty($event['RelatedAttribute'][$object['id']])) {
            echo $this->element('Events/View/attribute_correlations', array(
              'scope' => 'Attribute',
              'object' => $object,
              'event' => $event,
            ));
          }
        ?>
      </ul>
    </td>
    <td class="shortish">
      <ul class="inline" style="margin:0px;">
        <?php
            if (!empty($object['Feed'])) {
                foreach ($object['Feed'] as $feed) {
                    $popover = '';
                    foreach ($feed as $k => $v) {
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
                    $liContents = '';
                    if ($isSiteAdmin) {
                        if ($feed['source_format'] == 'misp') {
                            $liContents .= sprintf(
                                '<form action="%s/feeds/previewIndex/%s" method="post" style="margin:0px;line-height:auto;">%s%s</form>',
                                $baseurl,
                                h($feed['id']),
                                sprintf(
                                    '<input type="hidden" name="data[Feed][eventid]" value="%s">',
                                    h(json_encode($feed['event_uuids'], true))
                                ),
                                sprintf(
                                    '<input type="submit" class="linkButton useCursorPointer" value="%s" data-toggle="popover" data-content="%s" data-trigger="hover" style="margin-right:3px;line-height:normal;vertical-align: text-top;" />',
                                    h($feed['id']),
                                    h($popover)
                                )
                            );
                        } else {
                            $liContents .= sprintf(
                                '<form>%s</form>',
                                sprintf(
                                    '<a href="%s/feeds/previewIndex/%s" style="margin-right:3px;" data-toggle="popover" data-content="%s" data-trigger="hover">%s</a>',
                                    $baseurl,
                                    h($feed['id']),
                                    h($popover),
                                    h($feed['id'])
                                )
                            );
                        }
                    } else {
                        $liContents .= sprintf(
                            '<span style="margin-right:3px;">%s</span>',
                            h($feed['id'])
                        );
                    }
                    echo sprintf(
                        '<li style="padding-right: 0px; padding-left:0px;">%s</li>',
                        $liContents
                    );
                }
            }
            if (!empty($object['Server'])) {
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
                            '<li style="padding-right: 0px; padding-left:0px;">%s</li>',
                            $liContents
                        );
                    }
                }
            }
        ?>
      </ul>
    </td>
    <td class="short">
      <div id = "Attribute_<?php echo $object['id']; ?>_to_ids_placeholder" class = "inline-field-placeholder"></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_to_ids_solid" class="inline-field-solid">
        <input type="checkbox" class="toids-toggle" id="toids_toggle_<?php echo h($object['id']); ?>" data-attribute-id="<?php echo h($object['id']); ?>" aria-label="<?php echo __('Toggle IDS flag');?>" title="<?php echo __('Toggle IDS flag');?>" <?php echo $object['to_ids'] ? 'checked' : ''; ?> >
      </div>
    </td>
    <td class="short" onmouseenter="quickEditHover(this, '<?php echo $editScope; ?>', '<?php echo $object['id']; ?>', 'distribution', <?php echo $event['Event']['id'];?>);">
      <?php
        $turnRed = '';
        if ($object['distribution'] == 0) $turnRed = 'style="color:red"';
      ?>
      <div id = "Attribute_<?php echo $object['id']; ?>_distribution_placeholder" class = "inline-field-placeholder"></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_distribution_solid" <?php echo $turnRed; ?> class="inline-field-solid">
        <?php
          if ($object['distribution'] == 4):
        ?>
            <a href="/sharing_groups/view/<?php echo h($object['sharing_group_id']); ?>"><?php echo h($object['SharingGroup']['name']);?></a>
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
      'tr_class' => $tr_class,
      'page' => $page
    ));
  ?>
  <?php if (!empty($includeDecayScore)): ?>
    <td class="decayingScoreField">
          <div id = "Attribute_<?php echo h($object['id']); ?>_score_solid" class="inline-field-solid">
            <?php echo $this->element('DecayingModels/View/attribute_decay_score', array('scope' => 'object', 'object' => $object, 'uselink' => true)); ?>
          </div>
    </td>
  <?php endif; ?>
  <td class="short action-links">
    <?php
        if ($object['deleted']):
          if ($isSiteAdmin || $mayModify):
      ?>
          <span class="icon-repeat useCursorPointer" title="<?php echo __('Restore attribute');?>" role="button" tabindex="0" aria-label="<?php echo __('Restore attribute');?>" onClick="deleteObject('attributes', 'restore', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
          <span class="fa fa-trash useCursorPointer" title="<?php echo __('Permanently delete attribute');?>" role="button" tabindex="0" aria-label="i<?php echo __('Permanently delete attribute');?>" onClick="deleteObject('attributes', 'delete', '<?php echo h($object['id']) . '/true'; ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
      <?php
          endif;
        else:
          if ($isAclAdd && ($isSiteAdmin || !$mayModify)):
            if (isset($modules) && isset($modules['types'][$object['type']])):
      ?>
        <span class="icon-asterisk useCursorPointer" title="<?php echo __('Query enrichment');?>" role="button" tabindex="0" aria-label="<?php echo __('Query enrichment');?>" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?php echo h($object['id']);?>/ShadowAttribute');" title="<?php echo __('Propose enrichment');?>">&nbsp;</span>
      <?php
            endif;
            if (isset($cortex_modules) && isset($cortex_modules['types'][$object['type']])):
      ?>
        <span class="icon-eye-open useCursorPointer" title="<?php echo __('Query Cortex');?>" role="button" tabindex="0" aria-label="<?php echo __('Query Cortex');?>" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?php echo h($object['id']);?>/ShadowAttribute/Cortex');" title="<?php echo __('Propose enrichment through Cortex');?>"></span>
      <?php
            endif;
      ?>
            <a href="<?php echo $baseurl;?>/shadow_attributes/edit/<?php echo $object['id']; ?>" title="<?php echo __('Propose Edit');?>" aria-label="<?php echo __('Propose Edit');?>" class="fa fa-comment useCursorPointer"></a>
            <span class="fa fa-trash useCursorPointer" title="<?php echo __('Propose Deletion');?>" role="button" tabindex="0" aria-label="Propose deletion" onClick="deleteObject('shadow_attributes', 'delete', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
      <?php
            if ($isSiteAdmin):
      ?>
              <span class="verticalSeparator">&nbsp;</span>
      <?php     endif;
          endif;
          if ($isSiteAdmin || $mayModify):
            if (isset($modules) && isset($modules['types'][$object['type']])):
      ?>
        <span class="icon-asterisk useCursorPointer" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?php echo h($object['id']);?>/Attribute');" title="<?php echo __('Add enrichment');?>" role="button" tabindex="0" aria-label="<?php echo __('Add enrichment');?>">&nbsp;</span>
      <?php
            endif;
            if (isset($cortex_modules) && isset($cortex_modules['types'][$object['type']])):
      ?>
        <span class="icon-eye-open useCursorPointer" onClick="simplePopup('<?php echo $baseurl;?>/events/queryEnrichment/<?php echo h($object['id']);?>/Attribute/Cortex');" title="<?php echo __('Add enrichment');?>" role="button" tabindex="0" aria-label="<?php echo __('Add enrichment via Cortex');?>"></span>
      <?php
            endif;
      ?>
            <a href="<?php echo $baseurl;?>/attributes/edit/<?php echo $object['id']; ?>" title="<?php echo __('Edit');?>" aria-label="<?php echo __('Edit');?>" class="fa fa-edit useCursorPointer"></a>
          <?php
            if (empty($event['Event']['publish_timestamp'])):
          ?>
            <span class="fa fa-trash useCursorPointer" title="<?php echo __('Permanently delete attribute');?>" role="button" tabindex="0" aria-label="i<?php echo __('Permanently delete attribute');?>" onClick="deleteObject('attributes', 'delete', '<?php echo h($object['id']) . '/true'; ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
          <?php
            else:
          ?>
            <span class="fa fa-trash useCursorPointer" title="<?php echo __('Soft-delete attribute');?>" role="button" tabindex="0" aria-label="<?php echo __('Soft-delete attribute');?>" onClick="deleteObject('attributes', 'delete', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
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
        'page' => $page,
        'fieldCount' => $fieldCount,
        'child' => $propKey == $lastElement ? 'last' : true,
        'objectContainer' => $child
      ));
    }
  }
?>
