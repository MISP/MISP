<?php
  $tr_class = '';
  $linkClass = 'white';
  $currentType = 'denyForm';
  $tr_class = 'tableHighlightBorderTop borderBlue';
  if ($object['deleted']) $tr_class .= ' lightBlueRow';
  else $tr_class .= ' blueRow';
  if (!empty($k)) {
    $tr_class .= ' row_' . h($k);
  }
?>
<tr id = "Object_<?php echo $object['id']; ?>_tr" class="<?php echo $tr_class; ?>" tabindex="0">
  <?php
    if ($mayModify):
  ?>
    <td style="width:10px;" data-position="<?php echo h($object['objectType']) . '_' . h($object['id']); ?>">
      <input id = "select_object_<?php echo $object['id']; ?>" class="select_object row_checkbox" type="checkbox" data-id="<?php echo $object['id'];?>" />
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
  <td class="short" colspan="2">
    <?php echo date('Y-m-d', $object['timestamp']); ?>
  </td>
  <td colspan="<?php echo $fieldCount -5;?>">
    <span class="bold">Name: </span><?php echo h($object['name']);?>
    <span class="fa fa-expand useCursorPointer" title="Expand or Collapse" role="button" tabindex="0" aria-label="Expand or Collapse" data-toggle="collapse" data-target="#Object_<?php echo h($object['id']); ?>_collapsible"></span>
    <br />
    <div id="Object_<?php echo $object['id']; ?>_collapsible" class="collapse">
      <span class="bold">Meta-category: </span><?php echo h($object['meta-category']);?><br />
      <span class="bold">Description: </span><?php echo h($object['description']);?><br />
      <span class="bold">Tempate: </span><?php echo h($object['name']) . ' v' . h($object['template_version']) . ' (' . h($object['template_uuid']) . ')'; ?>
    </div>
    <span class="bold">References: </span>
    <?php
      echo count($object['ObjectReference']);
      if (!empty($object['ObjectReference'])):
    ?>
        <span class="fa fa-expand useCursorPointer" title="Expand or Collapse" role="button" tabindex="0" aria-label="Expand or Collapse" data-toggle="collapse" data-target="#Object_<?php echo h($object['id']); ?>_references_collapsible"></span>
    <?php
      endif;
    ?>
    <span class="fa fa-plus-square useCursorPointer" title="Add reference" role="button" tabindex="0" aria-label="Add reference" onClick="genericPopup('<?php echo '/objectReferences/add/' . h($object['id']);?>', '#popover_form');"></span>
    <div id="Object_<?php echo $object['id']; ?>_references_collapsible" class="collapse">
    <?php
      foreach ($object['ObjectReference'] as $reference):
        $uuid = empty($reference['Object']) ? $reference['Attribute']['uuid'] : $reference['Object']['uuid'];
    ?>
        &nbsp;&nbsp;<a class="bold white useCursorPointer" onClick="pivotObjectReferences('<?php echo h($currentUri); ?>', '<?php echo $uuid; ?>')"><?php echo h($reference['relationship_type']) . ' ' . array('Attribute', 'Object')[$reference['referenced_type']];?></a><br />
    <?php
      endforeach;
    ?>
    </div>
  </td>
  <td class="shortish">
    <?php
      $turnRed = '';
      if ($object['objectType'] == 0 && $object['distribution'] == 0) $turnRed = 'style="color:red"';
    ?>
    <div id = "<?php echo $currentType . '_' . $object['id'] . '_distribution_placeholder'; ?>" class = "inline-field-placeholder"></div>
    <div id = "<?php echo $currentType . '_' . $object['id'] . '_distribution_solid'; ?>" <?php echo $turnRed; ?> class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'distribution', <?php echo $event['Event']['id'];?>);">
      <?php
        if ($object['objectType'] == 0) {
          if ($object['distribution'] == 4):
      ?>
          <a href="/sharing_groups/view/<?php echo h($object['sharing_group_id']); ?>"><?php echo h($object['SharingGroup']['name']);?></a>
      <?php
          else:
            echo h($shortDist[$object['distribution']]);
          endif;
        }
      ?>&nbsp;
    </div>
  </td>
  <td>&nbsp;</td>
  <td>&nbsp;</td>
  <td class="short action-links">
    <?php
      if ($mayModify && empty($object['deleted'])):
    ?>
        <a href="<?php echo $baseurl;?>/objects/edit/<?php echo $object['id']; ?>" title="Edit" class="icon-edit icon-white useCursorPointer"></a>
        <span class="icon-trash icon-white useCursorPointer" title="Delete object" role="button" tabindex="0" aria-label="Delete attribute" onClick="deleteObject('objects', 'delete', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
    <?php
      elseif ($mayModify):
    ?>
        <span class="icon-trash icon-white useCursorPointer" title="Delete object" role="button" tabindex="0" aria-label="Delete attribute" onClick="deleteObject('objects', 'delete', '<?php echo h($object['id']) . '/true'; ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
    <?php
      endif;
    ?>
  </td>
</tr>
<?php
  if (!empty($object['Attribute'])) {
    end($object['Attribute']);
    $lastElement = key($object['Attribute']);
    foreach ($object['Attribute'] as $attrKey => $attribute) {
      echo $this->element('/Events/View/row_' . $attribute['objectType'], array(
        'object' => $attribute,
        'mayModify' => $mayModify,
        'mayChangeCorrelation' => $mayChangeCorrelation,
        'page' => $page,
        'fieldCount' => $fieldCount,
        'child' => $attrKey == $lastElement ? 'last' : true
      ));
    }
  }
?>
