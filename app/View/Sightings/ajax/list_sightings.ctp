<?php
// Calling `__` method for every sighting can be surprisingly quite slow, so better to call just once
$deleteSightingTitle = __('Delete sighting');
?>
<div>
    <div id="org_id" class="hidden"><?php echo h($org_id); ?></div>
    <table class="table table-striped table-hover table-condensed" style="display:block; overflow-y:auto;max-height:500px;">
    <tr>
        <th><?php echo __('Date');?></th>
        <th><?php echo __('Organisation');?></th>
        <th><?php echo __('Type');?></th>
        <th><?php echo __('Source');?></th>
        <th><?php echo __('Event ID');?></th>
        <th><?php echo __('Attribute ID');?></th>
        <th class="actions"><?php echo __('Actions');?></th>
    </tr>
<?php
    foreach ($sightings as $item):
?>
    <tr>
        <td class="short"><?php echo date('Y-m-d H:i:s', $item['Sighting']['date_sighting']);?></td>
        <td class="short">
          <?php if ($item['Organisation']['name']) {
              echo $this->OrgImg->getOrgImg(array('name' => $item['Organisation']['name'], 'id' => $item['Sighting']['org_id'], 'size' => 24));
          }
          ?>
        </td>
        <td class="short"><?= $types[$item['Sighting']['type']] ?></td>
        <td class="short"><?= h($item['Sighting']['source']) ?></td>
        <td class="short"><?= h($item['Sighting']['event_id']) ?></td>
        <td class="short"><?= h($item['Sighting']['attribute_id']) ?></td>
        <td class="short action-links">
          <?php
            if ($isSiteAdmin || ($item['Sighting']['org_id'] == $me['org_id'] && $isAclAdd)):
          ?>
            <span class="fa fa-trash useCursorPointer" title="<?= $deleteSightingTitle ?>" role="button" tabindex="0" aria-label="<?= $deleteSightingTitle ?>" onClick="quickDeleteSighting('<?= h($item['Sighting']['id']) ?>', '<?= h($rawId) ?>', '<?= h($context) ?>');"></span>
          <?php
            endif;
                ?>
        </td>
    </tr>
<?php
    endforeach;
?>
    </table>
</div>
