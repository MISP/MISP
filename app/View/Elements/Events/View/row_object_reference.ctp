<span class="bold"><?php echo __('References: ');?></span>
<?php
  $refCount = count($object['ObjectReference']);
  if ($deleted) {
    $temp = array(0, 0);
    foreach ($object['ObjectReference'] as $objectRef) {
      if ($objectRef['deleted']) {
        $temp[1]++;
      } else {
        $temp[0]++;
      }
    }
    $refCount = $temp[0];
    if ($temp[1] != 0) {
      $refCount .= ' <span class="strikethrough">' . $temp[1] . '</span>';
    }
  }
  echo $refCount . ' ';
  if (!empty($object['ObjectReference'])):
?>
    <span class="fa fa-expand useCursorPointer" title="<?php echo __('Expand or Collapse');?>" role="button" tabindex="0" aria-label="<?php echo __('Expand or Collapse');?>" data-toggle="collapse" data-target="#Object_<?php echo h($object['id']); ?>_references_collapsible"></span>
<?php
  endif;
?>
<?php
  if ($mayModify):
?>
    <span class="fa fa-plus-square useCursorPointer" title="<?php echo __('Add reference');?>" role="button" tabindex="0" aria-label="<?php echo __('Add reference');?>" onClick="genericPopup('<?php echo '/objectReferences/add/' . h($object['id']);?>', '#popover_form');"></span>
<?php
  endif;
?>
<div id="Object_<?php echo $object['id']; ?>_references_collapsible" class="collapse">
<?php
  foreach ($object['ObjectReference'] as $reference):
    if (!empty($reference['Object'])) {
      $uuid = $reference['Object']['uuid'];
      $output = ' (' . $reference['Object']['name'] . ': ' . $reference['Object']['name'] . ')';
      $objectType = 'Object';
    } else {
      $uuid = $reference['Attribute']['uuid'];
      $output = ' (' . $reference['Attribute']['category'] . '/' . $reference['Attribute']['type'] . ': "' . $reference['Attribute']['value'] . '")';
      $objectType = 'Attribute';
    }
    $uuid = empty($reference['Object']) ? $reference['Attribute']['uuid'] : $reference['Object']['uuid'];
    $idref = $reference['deleted'] ? $reference['id'] . '/1' : $reference['id'];
?>
    &nbsp;&nbsp;
    <a class="bold white useCursorPointer <?php echo $reference['deleted'] ? 'strikethrough' : ''; ?>" onClick="pivotObjectReferences('<?php echo h($currentUri); ?>', '<?php echo $uuid; ?>')">
      <?php echo h($reference['relationship_type']) . ' ' . $objectType . ' ' . $reference['referenced_id'] . h($output);?>
    </a>
    <span class="icon-trash icon-white useCursorPointer" title="<?php echo __('Delete object reference');?>" role="button" tabindex="0" aria-label="<?php echo __('Delete object reference');?>" onClick="deleteObject('object_references', 'delete', '<?php echo h($idref); ?>', '<?php echo h($event['Event']['id']); ?>');"></span>
    <br />
<?php
  endforeach;
?>
</div>
