<?php
  $tr_class = 'darkOrangeRow';
  $linkClass = 'white';
  $currentType = 'denyForm';
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
  $identifier = (empty($k)) ? '' : ' id="row_' . h($k) . '" tabindex="0"';
?>
<tr id = "proposal<?php echo '_' . $object['id'] . '_tr'; ?>" class="<?php echo $tr_class; ?>" <?php echo $identifier; ?>>
  <?php if ($mayModify): ?>
    <td style="width:10px;" data-position="<?php echo h($object['objectType']) . '_' . h($object['id']); ?>">
      <input id = "select_proposal_<?php echo $object['id']; ?>" class="select_proposal row_checkbox" type="checkbox" data-id="<?php echo $object['id'];?>" />
    </td>
  <?php endif; ?>
    <td class="short context hidden">
      <?php
        echo $object['objectType'] == 0 ? h($object['id']) : '&nbsp;';
      ?>
    </td>
    <td class="short context hidden">
      <?php echo $object['objectType'] == 0 ? h($object['uuid']) : '&nbsp;'; ?>
    </td>
    <td class="short">
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_timestamp_solid'; ?>">
        <?php
          if (isset($object['timestamp'])) echo date('Y-m-d', $object['timestamp']);
          else echo '&nbsp';
        ?>
      </div>
    </td>
    <td class="short">
  <?php
    if ($object['objectType'] != 0) {
      if (isset($object['Org']['name'])) {
        $imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . 'orgs' . DS . h($object['Org']['name']) . '.png';
        if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($object['Org']['name']) . '.png', array('alt' => h($object['Org']['name']), 'title' => h($object['Org']['name']), 'style' => 'width:24px; height:24px'));
        else echo h($object['Org']['name']);
      }
    } else { ?>
    &nbsp;
  <?php
    }
  ?>
    </td>
    <td class="short">
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_category_placeholder'; ?>" class = "inline-field-placeholder"></div>
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_category_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'category', <?php echo $event['Event']['id'];?>);">
        <?php echo h($object['category']); ?>
      </div>
    </td>
    <td class="short">
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_type_placeholder'; ?>" class = "inline-field-placeholder"></div>
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_type_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'type', <?php echo $event['Event']['id'];?>);">
        <?php echo h($object['type']); ?>
      </div>
    </td>
    <td id="<?php echo h($currentType) . '_' . h($object['id']) . '_container'; ?>" class="showspaces limitedWidth shortish">
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_value_placeholder'; ?>" class = "inline-field-placeholder"></div>
      <?php
        if ('attachment' !== $object['type'] && 'malware-sample' !== $object['type']) $editable = ' ondblclick="activateField(\'' . $currentType . '\', \'' . $object['id'] . '\', \'value\', \'' . $event['Event']['id'] . '\');"';
        else $editable = '';
      ?>
      <div id = "<?php echo $currentType; ?>_<?php echo $object['id']; ?>_value_solid" class="inline-field-solid" <?php echo $editable; ?>>
        <span <?php if (Configure::read('Plugin.Enrichment_hover_enable') && isset($modules) && isset($modules['hover_type'][$object['type']])) echo 'class="eventViewAttributeHover" data-object-type="' . h($currentType) . '" data-object-id="' . h($object['id']) . '"'?>>
      <?php
          echo $this->element('/Events/View/value_field', array('object' => $object, 'linkClass' => $linkClass));
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
            echo ' <span class="icon-warning-sign icon-white" data-placement="right" data-toggle="popover" data-content="' . h($temp) . '" data-trigger="hover">&nbsp;</span>';
          }
        ?>
      </div>
    </td>
    <td class="shortish">
      <?php
        if ($object['objectType'] == 0):
      ?>
        <div class="attributeTagContainer">
          &nbsp;
        </div>
      <?php
        else:
      ?>
        &nbsp;
      <?php
        endif;
      ?>
    </td>
    <td class="showspaces bitwider">
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_comment_placeholder'; ?>" class = "inline-field-placeholder"></div>
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_comment_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'comment', <?php echo $event['Event']['id'];?>);">
        <?php echo nl2br(h($object['comment'])); ?>&nbsp;
      </div>
    </td>
    <td class="short" style="padding-top:3px;">&nbsp;</td>
    <td class="shortish">
      <ul class="inline" style="margin:0px;">
        <?php
          if (!empty($event['RelatedShadowAttribute'][$object['id']])) {
            foreach ($event['RelatedShadowAttribute'][$object['id']] as $relatedAttribute) {
              $relatedData = array('Event info' => $relatedAttribute['info'], 'Correlating Value' => $relatedAttribute['value'], 'date' => isset($relatedAttribute['date']) ? $relatedAttribute['date'] : 'N/A');
              $popover = '';
              foreach ($relatedData as $k => $v) {
                $popover .= '<span class=\'bold black\'>' . h($k) . '</span>: <span class="blue">' . h($v) . '</span><br />';
              }
              echo '<li style="padding-right: 0px; padding-left:0px;" data-toggle="popover" data-content="' . h($popover) . '" data-trigger="hover"><span>';
              $correlationClass = 'white' . ($relatedAttribute['org_id'] == $me['org_id'] ? ' bold' : '');
              echo $this->Html->link($relatedAttribute['id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['id'], true, $event['Event']['id']), array('class' => $correlationClass));
              echo "</span></li>";
              echo ' ';
            }
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
              <li style="padding-right: 0px; padding-left:0px;"  data-toggle="popover" data-content="<?php echo h($popover);?>" data-trigger="hover"><span>
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
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_to_ids_placeholder'; ?>" class = "inline-field-placeholder"></div>
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_to_ids_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'to_ids', <?php echo $event['Event']['id'];?>);">
        <?php
          if ($object['to_ids']) echo 'Yes';
          else echo 'No';
        ?>
      </div>
    </td>
    <td class="shortish">&nbsp;</td>
  <?php
    if (Configure::read('Plugin.Sightings_enable') !== false):
  ?>
  <td class="shortish">&nbsp;</td>
  <td class="short">&nbsp;</td>
  <?php
    endif;
  ?>
  <td class="short action-links">
    <?php
        if (($event['Orgc']['id'] == $me['org_id'] && $mayModify) || $isSiteAdmin) {
          echo $this->Form->create('Shadow_Attribute', array('id' => 'ShadowAttribute_' . $object['id'] . '_accept', 'url' => '/shadow_attributes/accept/' . $object['id'], 'style' => 'display:none;'));
          echo $this->Form->end();
        ?>
          <span class="icon-ok icon-white useCursorPointer" title="Accept Proposal" role="button" tabindex="0" aria-label="Accept proposal" onClick="acceptObject('shadow_attributes', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
        <?php
        }
        if (($event['Orgc']['id'] == $me['org_id'] && $mayModify) || $isSiteAdmin || ($object['org_id'] == $me['org_id'])) {
        ?>
          <span class="icon-trash icon-white useCursorPointer" title="Discard proposal" role="button" tabindex="0" aria-label="Discard proposal" onClick="deleteObject('shadow_attributes', 'discard' ,'<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
        <?php
        }
    ?>
  </td>
</tr>
