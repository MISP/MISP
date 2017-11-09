<span class="bold">References: </span>
<?php
  $refCount = count($object['ObjectReference']);
  echo $refCount . ' ';
  if (!empty($object['ObjectReference'])):
?>
    <span class="fa fa-expand useCursorPointer" title="Expand or Collapse" role="button" tabindex="0" aria-label="Expand or Collapse" data-toggle="collapse" data-target="#Object_<?php echo h($object['uuid']); ?>_references_collapsible"></span>
<?php
  endif;
?>
<div id="Object_<?php echo $object['uuid']; ?>_references_collapsible" class="collapse">
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
    $idref = $reference['uuid'];
?>
    &nbsp;&nbsp;
    <div class="bold white useCursorPointer">
      <?php echo h($reference['relationship_type']) . ' ' . $objectType . ' ' . $reference['referenced_uuid'] . h($output);?>
    </div>
    <br />
<?php
  endforeach;
?>
</div>
