<span class="bold">References: </span>
<?php
  $refCount = count($object['ObjectReference']);
  echo $refCount . ' ';
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
    $idref = $reference['id'];
?>
    &nbsp;&nbsp;
    <a class="bold white useCursorPointer" onClick="pivotObjectReferences('<?php echo h($currentUri); ?>', '<?php echo $uuid; ?>')">
      <?php echo h($reference['relationship_type']) . ' ' . $objectType . ' ' . $reference['referenced_id'] . h($output);?>
    </a>
    <br />
<?php
  endforeach;
?>
</div>
