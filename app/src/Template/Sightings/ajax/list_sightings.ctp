<div>
	<div id="org_id" class="hidden"><?php echo h($org_id); ?></div>
	<table class="table table-striped table-hover table-condensed" style="display:block; overflow-y:auto;max-height:500px;">
	<tr>
		<th>Date</th>
		<th>Organisation</th>
		<th>Type</th>
		<th>Source</th>
		<th>Event ID</th>
		<th>Attribute ID</th>
		<th class="actions">Actions</th>
	</tr>
<?php
	foreach ($sightings as $item):
?>
		<tr>
			<td class="short"><?php echo date('Y-m-d H:i:s', $item['Sighting']['date_sighting']);?></td>
		<td class="short">
		  <?php
			$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . 'orgs' . DS . h($item['Organisation']['name']) . '.png';
			if (file_exists($imgAbsolutePath)):
			  echo $this->Html->image('orgs/' . h($item['Organisation']['name']) . '.png', array('alt' => h($item['Organisation']['name']), 'title' => h($item['Organisation']['name']), 'style' => 'width:24px; height:24px'));
			else:
			  echo h($item['Organisation']['name']);
			endif;

		  ?>
		</td>
		<td class="short">
		  <?php
			echo $types[$item['Sighting']['type']];
		  ?>
		</td>
		<td class="short"><?php echo h($item['Sighting']['source']);?></td>
		<td class="short"><?php echo h($item['Sighting']['event_id']);?></td>
		<td class="short"><?php echo h($item['Sighting']['attribute_id']);?></td>
			<td class="short action-links">
		  <?php
			if ($isSiteAdmin || ($item['Sighting']['org_id'] == $me['org_id'] && $isAclAdd)):
		  ?>
			<span class="icon-trash useCursorPointer" title="Delete sighting" role="button" tabindex="0" aria-label="Delete sighting" onClick="quickDeleteSighting('<?php echo h($item['Sighting']['id']); ?>', '<?php echo h($rawId); ?>', '<?php echo h($context); ?>');"></span>
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
