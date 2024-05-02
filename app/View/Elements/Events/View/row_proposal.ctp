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
    <td style="width:10px">
      <input class="select_proposal" type="checkbox" aria-label="<?php __('Select proposal');?>" data-id="<?php echo $object['id'];?>">
    </td>
  <?php endif; ?>
  <td class="short context hidden">
    <?php
      echo h($object['id']);
    ?>
  </td>
  <td class="short context hidden uuid">
        <span class="quickSelect"><?php echo h($object['uuid']); ?></span>
      </td>
  <td class="short context hidden">
      <?php echo $this->element('/Events/View/seen_field', array('object' => $object)); ?>
  </td>
  <td class="short">
      <?php
        if (isset($object['timestamp'])) echo $this->Time->date($object['timestamp']);
        else echo '&nbsp';
      ?>
  </td>
  <td class="short context">
      <?php
            $notes = !empty($object['Note']) ? $object['Note'] : [];
            $opinions = !empty($object['Opinion']) ? $object['Opinion'] : [];
            $relationships = !empty($object['Relationship']) ? $object['Relationship'] : [];
            $relationshipsInbound = !empty($object['RelationshipInbound']) ? $object['RelationshipInbound'] : [];
            echo $this->element('genericElements/shortUuid', [
                'uuid' => $object['uuid']
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
    if (isset($object['Org']['name'])) {
      echo $this->OrgImg->getOrgImg(array('name' => $object['Org']['name'], 'id' => $object['Org']['id'], 'size' => 24));
    }
  ?>
  </td>
  <?php endif; ?>
  <td class="short">
      <?php echo h($object['category']); ?>
  </td>
  <td class="short">
      <?php echo h($object['type']); ?>
  </td>
  <td id="<?php echo h($currentType) . '_' . h($object['id']) . '_container'; ?>" class="showspaces limitedWidth shortish">
    <?= $this->element('/Events/View/value_field', array('object' => $object, 'linkClass' => $linkClass)); ?>
  </td>
  <td class="shortish">&nbsp;</td>
  <td class="shortish">&nbsp;</td>
  <td class="showspaces bitwider">
      <?php echo nl2br(h($object['comment']), false); ?>
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
              'withPivot' => true,
          ));
        }
      ?>
    </ul>
  </td>
  <?php if ($me['Role']['perm_view_feed_correlations']): ?>
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
  <?php endif; ?>
  <td class="short">
      <?= $object['to_ids'] ? __('Yes') : __('No') ?>
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
          <span class="fas fa-check white useCursorPointer" title="<?php echo __('Accept Proposal');?>" role="button" tabindex="0" aria-label="<?php echo __('Accept proposal');?>" onclick="acceptObject('shadow_attributes', '<?php echo $object['id']; ?>');"></span>
        <?php
        }
        if (($event['Orgc']['id'] == $me['org_id'] && $mayModify) || $isSiteAdmin || ($object['org_id'] == $me['org_id'])) {
        ?>
          <span class="fa fa-trash white useCursorPointer" title="<?php echo __('Discard proposal');?>" role="button" tabindex="0" aria-label="<?php echo __('Discard proposal');?>" onclick="deleteObject('shadow_attributes', 'discard' ,'<?php echo $object['id']; ?>');"></span>
        <?php
        }
    ?>
  </td>
</tr>
