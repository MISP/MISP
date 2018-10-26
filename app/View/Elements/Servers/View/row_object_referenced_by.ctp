<span class="bold"><?php echo __('Referenced by');?>: </span>
<?php
  $refCount = count($object['referenced_by']);
  echo $refCount;
  if (!empty($object['referenced_by'])):
?>
    <span class="fa fa-expand useCursorPointer" title="<?php echo __('Expand or Collapse');?>" role="button" tabindex="0" aria-label="<?php echo __('Expand or Collapse');?>" data-toggle="collapse" data-target="#Object_<?php echo h($object['id']); ?>_referenced_by_collapsible"></span>
<?php
  endif;
?>
<div id="Object_<?php echo $object['id']; ?>_referenced_by_collapsible" class="collapse">
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
        <a class="bold white useCursorPointer" onClick="pivotObjectReferences('<?php echo h($currentUri); ?>', '<?php echo $uuid; ?>')">
          <?php echo h($ref['relationship_type']) . ' ' . ucfirst($type) . ' ' . h($ref['id']) . h($output);?>
        </a>
      <br />
<?php
    endforeach;
  endforeach;
?>
</div>
