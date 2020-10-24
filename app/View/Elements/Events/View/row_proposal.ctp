<?php
  $tr_class = 'darkOrangeRow';
  $linkClass = 'white';
  $currentType = 'denyForm';
  if ($event['Event']['id'] != $object['event_id']) {
    if (!$isSiteAdmin && $event['extensionEvents'][$object['event_id']]['Orgc']['id'] != $me['org_id']) {
      $mayModify = false;
    }
  }
  if (!empty($objectContainer)) {
    if (!empty($child)) {
      if ($child === 'last') {
        $tr_class .= ' tableInsetOrangeLast';
      } else {
        $tr_class .= ' tableInsetOrangeMiddle';
      }
    } else {
      $tr_class .= ' tableInsetOrange';
    }
    if ($child === 'last') {
      $tr_class .= ' tableHighlightBorderBottom borderBlue';
    } else {
      $tr_class .= ' tableHighlightBorderCenter borderBlue';
    }
  } else {
    if (!empty($child)) {
      if ($child === 'last') {
        $tr_class .= ' tableHighlightBorderBottom borderOrange';
      } else {
        $tr_class .= ' tableHighlightBorderCenter borderOrange';
      }
    } else {
      $tr_class .= ' tableHighlightBorder borderOrange';
    }
  }
?>
<tr id="proposal_<?= $object['id'] ?>_tr" class="<?php echo $tr_class; ?>">
  <?php if ($mayModify): ?>
    <td style="width:10px;" data-position="<?php echo h($object['objectType']) . '_' . h($object['id']); ?>">
      <input id = "select_proposal_<?php echo $object['id']; ?>" class="select_proposal row_checkbox" type="checkbox" aria-label="<?php __('Select proposal');?>" data-id="<?php echo $object['id'];?>" />
    </td>
  <?php endif; ?>
  <td class="short context hidden">
    <?php
      echo h($object['id']);
    ?>
  </td>
  <td class="short context hidden uuid quickSelect"><?= h($object['uuid']) ?></td>
  <td class="short context hidden">
      <?php echo $this->element('/Events/View/seen_field', array('object' => $object)); ?>
  </td>
  <td class="short">
    <div id="<?php echo $currentType . '_' . $object['id'] . '_timestamp_solid'; ?>">
      <?php
        if (isset($object['timestamp'])) echo date('Y-m-d', $object['timestamp']);
        else echo '&nbsp';
      ?>
    </div>
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
    if (isset($object['Org']['name'])) {
      echo $this->OrgImg->getOrgImg(array('name' => $object['Org']['name'], 'id' => $object['Org']['id'], 'size' => 24));
    }
  ?>
  </td>
  <td class="short">
    <div id="<?php echo $currentType . '_' . $object['id'] . '_category_placeholder'; ?>" class="inline-field-placeholder"></div>
    <div id="<?php echo $currentType . '_' . $object['id'] . '_category_solid'; ?>" class="inline-field-solid">
      <?php echo h($object['category']); ?>
    </div>
  </td>
  <td class="short">
    <div id="<?php echo $currentType . '_' . $object['id'] . '_type_placeholder'; ?>" class="inline-field-placeholder"></div>
    <div id="<?php echo $currentType . '_' . $object['id'] . '_type_solid'; ?>" class="inline-field-solid">
      <?php echo h($object['type']); ?>
    </div>
  </td>
  <td id="<?php echo h($currentType) . '_' . h($object['id']) . '_container'; ?>" class="showspaces limitedWidth shortish">
    <div id="<?php echo $currentType . '_' . $object['id'] . '_value_placeholder'; ?>" class="inline-field-placeholder"></div>
    <div id="<?php echo $currentType; ?>_<?php echo $object['id']; ?>_value_solid" class="inline-field-solid">
    <?php
        echo $this->element('/Events/View/value_field', array('object' => $object, 'linkClass' => $linkClass));
    ?>
    </div>
  </td>
  <td class="shortish">&nbsp;</td>
  <td class="shortish">&nbsp;</td>
  <td class="showspaces bitwider">
    <div id="<?php echo $currentType . '_' . $object['id'] . '_comment_placeholder'; ?>" class="inline-field-placeholder"></div>
    <div id="<?php echo $currentType . '_' . $object['id'] . '_comment_solid'; ?>" class="inline-field-solid">
      <?php echo nl2br(h($object['comment'])); ?>&nbsp;
    </div>
  </td>
  <td class="short" style="padding-top:3px;">&nbsp;</td>
  <td class="shortish">
    <ul class="inline" style="margin:0px;">
      <?php
        if (!empty($event['RelatedShadowAttribute'][$object['id']])) {
          echo $this->element('Events/View/attribute_correlations', array(
            'scope' => 'ShadowAttribute',
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
              $popover .= '<span class=\'bold black\'>' . Inflector::humanize(h($k)) . '</span>: <span class="blue">' . h($v) . '</span><br />';
            endforeach;
          ?>
            <li style="padding-right: 0px; padding-left:0px;" data-toggle="popover" data-content="<?php echo h($popover);?>" data-trigger="hover"><span>
              <?php
                if ($isSiteAdmin):
                  echo $this->Html->link($feed['id'], array('controller' => 'feeds', 'action' => 'previewIndex', $feed['id']), array('style' => 'margin-right:3px;'));
                else:
              ?>
                <span style="margin-right:3px;"><?php echo h($feed['id']);?></span>
              <?php
                endif;
              endforeach;
              ?>
            </li>
      <?php
        endif;
      ?>
    </ul>
  </td>
  <td class="short">
    <div id="<?php echo $currentType . '_' . $object['id'] . '_to_ids_placeholder'; ?>" class="inline-field-placeholder"></div>
    <div id="<?php echo $currentType . '_' . $object['id'] . '_to_ids_solid'; ?>" class="inline-field-solid">
      <?php
        if ($object['to_ids']) echo 'Yes';
        else echo 'No';
      ?>
    </div>
  </td>
  <td class="shortish">&nbsp;</td>
  <td class="shortish">&nbsp;</td>
  <td class="short">&nbsp;</td>
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
        if (($event['Orgc']['id'] == $me['org_id'] && $mayModify) || $isSiteAdmin) {
          echo $this->Form->create('Shadow_Attribute', array('id' => 'ShadowAttribute_' . $object['id'] . '_accept', 'url' => $baseurl . '/shadow_attributes/accept/' . $object['id'], 'style' => 'display:none;'));
          echo $this->Form->end();
        ?>
          <span class="fas fa-check white useCursorPointer" title="<?php echo __('Accept Proposal');?>" role="button" tabindex="0" aria-label="<?php echo __('Accept proposal');?>" onClick="acceptObject('shadow_attributes', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
        <?php
        }
        if (($event['Orgc']['id'] == $me['org_id'] && $mayModify) || $isSiteAdmin || ($object['org_id'] == $me['org_id'])) {
        ?>
          <span class="fa fa-trash white useCursorPointer" title="<?php echo __('Discard proposal');?>" role="button" tabindex="0" aria-label="<?php echo __('Discard proposal');?>" onClick="deleteObject('shadow_attributes', 'discard' ,'<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
        <?php
        }
    ?>
  </td>
</tr>
