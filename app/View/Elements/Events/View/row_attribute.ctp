<?php
  $tr_class = '';
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
    if ($mayModify || $extended):
  ?>
      <td style="width:10px;" data-position="<?php echo h($object['objectType']) . '_' . h($object['id']); ?>">
      <?php
        if ($mayModify):
      ?>
          <input id = "select_<?php echo $object['id']; ?>" class="select_attribute row_checkbox" type="checkbox" data-id="<?php echo $object['id'];?>" />
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
      if ($extended):
    ?>
      <td class="short">
        <?php echo '<a href="' . $baseurl . '/events/view/' . h($object['event_id']) . '">' . h($object['event_id']) . '</a>'; ?>
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
    <td class="short">
      <div id = "Attribute_<?php echo $object['id']; ?>_category_placeholder" class = "inline-field-placeholder"></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_category_solid" class="inline-field-solid" ondblclick="activateField('<?php echo $editScope; ?>', '<?php echo $object['id']; ?>', 'category', <?php echo $event['Event']['id'];?>);">
        <?php echo h($object['category']); ?>
      </div>
    </td>
    <td class="short">
      <?php
        if (!empty($object['object_relation'])):
      ?>
          <div class="bold"><?php echo h($object['object_relation']); ?>:</div>
      <?php
        endif;
      ?>
      <div></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_type_placeholder" class = "inline-field-placeholder"></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_type_solid" class="inline-field-solid" ondblclick="activateField('<?php echo $editScope; ?>', '<?php echo $object['id']; ?>', 'type', <?php echo $event['Event']['id'];?>);">
        <?php echo h($object['type']); ?>
      </div>
    </td>
    <td id="Attribute_<?php echo h($object['id']); ?>_container" class="showspaces limitedWidth shortish">
      <div id="Attribute_<?php echo $object['id']; ?>_value_placeholder" class="inline-field-placeholder"></div>
      <?php
        if ('attachment' !== $object['type'] && 'malware-sample' !== $object['type']) $editable = ' ondblclick="activateField(\'' . $editScope . '\', \'' . $object['id'] . '\', \'value\', \'' . $event['Event']['id'] . '\');"';
        else $editable = '';
      ?>
      <div id = "Attribute_<?php echo $object['id']; ?>_value_solid" class="inline-field-solid" <?php echo $editable; ?>>
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
            echo ' <span class="icon-warning-sign" data-placement="right" data-toggle="popover" data-content="' . h($temp) . '" data-trigger="hover" data-placement="right">&nbsp;</span>';
          }
        ?>
      </div>
    </td>
    <td class="shortish">
      <div class="attributeTagContainer" id="#Attribute_<?php echo h($object['id']);?>_tr .attributeTagContainer">
        <?php echo $this->element('ajaxAttributeTags', array('attributeId' => $object['id'], 'attributeTags' => $object['AttributeTag'], 'tagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id']) )); ?>
      </div>
    </td>
    <td class="short">
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
    <td class="showspaces bitwider">
      <div id = "Attribute_<?php echo $object['id']; ?>_comment_placeholder" class = "inline-field-placeholder"></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_comment_solid" class="inline-field-solid" ondblclick="activateField('<?php echo $editScope; ?>', '<?php echo $object['id']; ?>', 'comment', <?php echo $event['Event']['id'];?>);">
        <?php echo nl2br(h($object['comment'])); ?>&nbsp;
      </div>
    </td>
    <td class="short" style="padding-top:3px;">
      <input
        id="correlation_toggle_<?php echo h($object['id']); ?>"
        class="correlation-toggle"
        type="checkbox"
        data-attribute-id="<?php echo h($object['id']); ?>"
        <?php
          echo $object['disable_correlation'] ? '' : ' checked';
          echo ($mayChangeCorrelation && !$event['Event']['disable_correlation']) ? '' : ' disabled';
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
          if (!empty($object['Feed'])):
            foreach ($object['Feed'] as $feed):
              $popover = '';
              foreach ($feed as $k => $v):
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
              endforeach;
            ?>
              <li style="padding-right: 0px; padding-left:0px;"><span>
                <?php
                  if ($isSiteAdmin):
                    if ($feed['source_format'] == 'misp'):
                  ?>
                      <form action="<?php echo $baseurl; ?>/feeds/previewIndex/1" method="post" style="margin:0px;line-height:auto;">
                        <input type="hidden" name="data[Feed][eventid]" value="<?php echo h(json_encode($feed['event_uuids'], true)); ?>">
                        <input type="submit" class="linkButton useCursorPointer" value="<?php echo h($feed['id']); ?>" data-toggle="popover" data-content="<?php echo h($popover);?>" data-trigger="hover" style="margin-right:3px;line-height:normal;vertical-align: text-top;" />
                      </form>
                  <?php
                    else:
                  ?>
                    <form>
                      <a href="<?php echo $baseurl; ?>/feeds/previewIndex/<?php echo h($feed['id']); ?>" style="margin-right:3px;"><?php echo h($feed['id']); ?></a>
                    </form>
                  <?php
                    endif;
                  else:
                ?>
                  <span style="margin-right:3px;"><?php echo h($feed['id']);?></span>
                <?php
                  endif;
                endforeach;
                ?>
              </li>
        <?php
          elseif (!empty($object['FeedHit'])):
        ?>
          <span class="icon-ok"></span>
        <?php
          endif;
        ?>
      </ul>
    </td>
    <td class="short">
      <div id = "Attribute_<?php echo $object['id']; ?>_to_ids_placeholder" class = "inline-field-placeholder"></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_to_ids_solid" class="inline-field-solid" ondblclick="activateField('<?php echo $editScope; ?>', '<?php echo $object['id']; ?>', 'to_ids', <?php echo $event['Event']['id'];?>);">
        <?php echo $object['to_ids'] ? 'Yes' : 'No'; ?>
      </div>
    </td>
    <td class="shortish">
      <?php
        $turnRed = '';
        if ($object['distribution'] == 0) $turnRed = 'style="color:red"';
      ?>
      <div id = "Attribute_<?php echo $object['id']; ?>_distribution_placeholder" class = "inline-field-placeholder"></div>
      <div id = "Attribute_<?php echo $object['id']; ?>_distribution_solid" <?php echo $turnRed; ?> class="inline-field-solid" ondblclick="activateField('<?php echo $editScope; ?>', '<?php echo $object['id']; ?>', 'distribution', <?php echo $event['Event']['id'];?>);">
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
  <td class="short action-links">
    <?php
        if ($object['deleted']):
          if ($isSiteAdmin || $mayModify):
      ?>
          <span class="icon-repeat useCursorPointer" title="<?php echo __('Restore attribute');?>" role="button" tabindex="0" aria-label="<?php echo __('Restore attribute');?>" onClick="deleteObject('attributes', 'restore', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
          <span class="icon-trash useCursorPointer" title="<?php echo __('Permanently delete attribute');?>" role="button" tabindex="0" aria-label="i<?php echo __('Permanently delete attribute');?>" onClick="deleteObject('attributes', 'delete', '<?php echo h($object['id']) . '/true'; ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
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
            <a href="<?php echo $baseurl;?>/shadow_attributes/edit/<?php echo $object['id']; ?>" title="<?php echo __('Propose Edit');?>" class="icon-share useCursorPointer"></a>
            <span class="icon-trash useCursorPointer" title="<?php echo __('Propose Deletion');?>" role="button" tabindex="0" aria-label="Propose deletion" onClick="deleteObject('shadow_attributes', 'delete', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
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
            <a href="<?php echo $baseurl;?>/attributes/edit/<?php echo $object['id']; ?>" title="<?php echo __('Edit');?>" class="icon-edit useCursorPointer"></a>
          <?php
            if (empty($event['Event']['publish_timestamp'])):
          ?>
            <span class="icon-trash useCursorPointer" title="<?php echo __('Permanently delete attribute');?>" role="button" tabindex="0" aria-label="i<?php echo __('Permanently delete attribute');?>" onClick="deleteObject('attributes', 'delete', '<?php echo h($object['id']) . '/true'; ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
          <?php
            else:
          ?>
            <span class="icon-trash useCursorPointer" title="<?php echo __('Soft-delete attribute');?>" role="button" tabindex="0" aria-label="<?php echo __('Soft-delete attribute');?>" onClick="deleteObject('attributes', 'delete', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
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
