<span class="bold"><?php echo __('Referenced by: ');?></span>
<?php
  $refCount = count($object['referenced_by']);
  echo $refCount;
  if (!empty($object['referenced_by'])):
?>
    <span class="fa fa-expand useCursorPointer" title="<?php echo __('Expand or Collapse');?>" role="button" tabindex="0" aria-label="<?php echo __('Expand or Collapse');?>" data-toggle="collapse" data-target="#Object_<?php echo h($object['uuid']); ?>_referenced_by_collapsible"></span>
<?php
  endif;
?>
<div id="Object_<?php echo $object['uuid']; ?>_referenced_by_collapsible" class="collapse">
<?php
  foreach ($object['referenced_by'] as $type => $reference):
    foreach ($reference as $ref):
      if ($type == 'object') {
        $uuid = $ref['uuid'];
        $output = ' (' . $ref['meta-category'] . ': ' . $ref['name'] . ')';
      } else {
        $uuid = $ref['uuid'];
        $output = ' (' . $ref['category'] . '/' . $ref['type'] . ': "' . $ref['value'] . '")';
      }
?>
      &nbsp;&nbsp;
        <span class="bold white useCursorPointer">
          <?php echo h($ref['relationship_type']) . ' ' . ucfirst($type) . ' ' . h($output);?>
        </span>
      <br />
<?php
    endforeach;
  endforeach;
?>
</div>
