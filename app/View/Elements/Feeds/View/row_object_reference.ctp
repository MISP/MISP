<span class="bold"><?php echo __('References: ');?></span>
<?php
  $refCount = empty($object['ObjectReference']) ? 0 : count($object['ObjectReference']);
  echo $refCount . ' ';
  if (!empty($object['ObjectReference'])):
?>
    <span class="fa fa-expand useCursorPointer" title="<?php echo __('Expand or Collapse');?>" role="button" tabindex="0" aria-label="<?php echo __('Expand or Collapse');?>" data-toggle="collapse" data-target="#Object_<?php echo h($object['uuid']); ?>_references_collapsible"></span>
<?php
  endif;
?>
<div id="Object_<?php echo $object['uuid']; ?>_references_collapsible" class="collapse">
<?php
  if (!empty($object['ObjectReference'])):
    foreach ($object['ObjectReference'] as $reference):
      if (!empty($reference['Object'])) {
        $uuid = $reference['Object']['uuid'];
        $output = ' (' . $reference['Object']['name'] . ': ' . $reference['Object']['name'] . ')';
        $objectType = 'Object';
      } else {
        $uuid = $reference['referenced_uuid'];
        $output = '';
        $objectType = 'Attribute';
      }
      $uuid = $reference['referenced_uuid'];
      $idref = $reference['uuid'];
?>
      <div class="bold white useCursorPointer">
        &nbsp;&nbsp;<?php echo h($reference['relationship_type']) . ' ' . $objectType . ' ' . $reference['referenced_uuid'] . h($output);?>
      </div>
<?php
    endforeach;
  endif;
?>
</div>
