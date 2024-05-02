<?php
  $tr_class = '';
  $linkClass = 'blue';
  $otherColour = 'blue';
  if (!empty($child)) {
    if ($child === 'last') {
      $tr_class .= ' tableHighlightBorderBottom borderBlue';
    } else {
      $tr_class .= ' tableHighlightBorderCenter borderBlue';
    }
  } else {
    $child = false;
  }
  if (!empty($object['deleted'])) {
    $tr_class .= ' deleted-attribute';
  }
  if (!empty($k)) {
    $tr_class .= ' row_' . h($k);
  }
?>
<tr id="Attribute_<?php echo h($object['uuid']); ?>_tr" class="<?php echo $tr_class; ?>" tabindex="0">
    <td class="short">
      <?php echo date('Y-m-d', $object['timestamp']); ?>
    </td>
    <td class="short">
      <?php echo $this->element('/Servers/View/seen_field', array('object' => $object)); ?>
    </td>
    <td class="short">
      <div id="Attribute_<?php echo $object['uuid']; ?>_category_solid" class="inline-field-solid">
        <?php echo h($object['category']); ?>
      </div>
    </td>
    <td class="short">
      <?php
        if (isset($object['object_relation'])):
      ?>
          <div class="bold"><?php echo h($object['object_relation']); ?>:</div>
      <?php
        endif;
      ?>
      <div></div>
      <div id="Attribute_<?php echo $object['uuid']; ?>_type_solid" class="inline-field-solid">
        <?php echo h($object['type']); ?>
      </div>
    </td>
    <td id="Attribute_<?php echo h($object['uuid']); ?>_container" class="showspaces limitedWidth shortish">
      <div id="Attribute_<?php echo $object['uuid']; ?>_value_solid" class="inline-field-solid">
        <span <?php if (Configure::read('Plugin.Enrichment_hover_enable') && isset($modules) && isset($modules['hover_type'][$object['type']])) echo 'class="eventViewAttributeHover" data-object-type="attributes" data-object-id="' . h($object['uuid']) . '"'?>>
          <?php
            echo $this->element('/Events/View/value_field', array('object' => $object, 'linkClass' => $linkClass));
          ?>
        </span>
        <?php
        if (isset($object['warnings'])) {
            $temp = '';
            foreach ($object['warnings'] as $warning) {
                $temp .= '<span class="bold">' . h($warning['match']) . ':</span> <span class="red">' . h($warning['warninglist_name']) . '</span><br>';
            }
            echo ' <span aria-label="' . __('warning') . '" role="img" tabindex="0" class="fa fa-exclamation-triangle" data-placement="right" data-toggle="popover" data-content="' . h($temp) . '" data-trigger="hover" data-placement="right">&nbsp;</span>';
        }
        ?>
      </div>
    </td>
    <td class="shortish">
      <div class="attributeTagContainer">
        <?php
          if (empty($object['Tag'])) echo "&nbsp;";
          else echo $this->element('ajaxAttributeTags', array('attributeId' => $object['uuid'], 'attributeTags' => $object['Tag'], 'tagAccess' => false));
        ?>
      </div>
    </td>
    <td class="showspaces bitwider">
      <div id="Attribute_<?php echo $object['uuid']; ?>_comment_solid" class="inline-field-solid">
        <?php echo nl2br(h($object['comment'])); ?>&nbsp;
      </div>
    </td>
    <td class="shortish">
      &nbsp;
    </td>
    <td class="shortish">
      &nbsp;
    </td>
    <td>
        <?php
        if ($object['distribution'] == 4) {
            echo h($object['SharingGroup']['name']);
        } else {
            echo $distributionLevels[$object['distribution']];
        }
        ?>
    </td>
    <td class="short">
      <div id="Attribute_<?php echo $object['uuid']; ?>_to_ids_solid" class="inline-field-solid">
        <?php echo $object['to_ids'] ? __('Yes') : __('No'); ?>
      </div>
    </td>
</tr>
