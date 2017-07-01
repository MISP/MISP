<?php
	$fixed_fields = array('synonyms', 'description', 'meta', 'authors', 'source');
	foreach ($event['Galaxy'] as $galaxy):
?>
		<div style="margin-left:10px;">
			<span title="<?php echo isset($galaxy['description']) ? h($galaxy['description']) : h($galaxy['name']);?>" class="bold blue" style="font-size:14px;">
				<?php echo h($galaxy['name']); ?>&nbsp;
				<a href="<?php echo $baseurl; ?>/galaxies/view/<?php echo h($galaxy['id']); ?>" class="icon-search" title="View details about this galaxy"></a>
			</span>
	<?php
		foreach ($galaxy['GalaxyCluster'] as $cluster):
	?>
			<div style="margin-left:8px;">
				<span class="bold blue expandable useCursorPointer"><span class="collapse-status" style="font-size: 16px;">+</span>&nbsp;<?php echo h($cluster['value']); ?></span>&nbsp;
				<a href="<?php echo $baseurl; ?>/galaxy_clusters/view/<?php echo h($cluster['id']); ?>" class="icon-search" title="View details about this cluster"></a>&nbsp;
				<a href="<?php echo $baseurl; ?>/events/index/searchtag:<?php echo h($cluster['tag_id']); ?>" class="icon-th-list" title="View all events containing this cluster."></a>
				<?php
					if ($isSiteAdmin || ($mayModify && $isAclTagger)) {
						echo $this->Form->postLink('',
							$baseurl . '/galaxy_clusters/detachFromEvent/' . $event['Event']['id'] . '/' . $cluster['tag_id'],
							array('class' => 'icon-trash', 'title' => 'Delete'),
							__('Are you sure you want to detach %s from this event?', h($cluster['value']))
						);
					}
				?>
				<div style="margin-left:15px;" class="hidden blue">
					<table style="width:100%">
						<?php
							$cluster_fields = array();
							if (isset($cluster['description'])) {
								$cluster_fields[] = array('key' => 'description', 'value' => $cluster['description']);
							}
							if (isset($cluster['meta']['synonyms'])) {
								$cluster_fields[] = array('key' => 'synonyms', 'value' => $cluster['meta']['synonyms']);
							}
							if (isset($cluster['source'])) {
								$cluster_fields[] = array('key' => 'source', 'value' => $cluster['source']);
							}
							if (isset($cluster['authors'])) {
								$cluster_fields[] = array('key' => 'authors', 'value' => $cluster['authors']);
							}
							if (!empty($cluster['meta'])) {
								foreach ($cluster['meta'] as $metaKey => $metaField) {
									if ($metaKey != 'synonyms') {
										$cluster_fields[] = array('key' => $metaKey, 'value' => $metaField);
									}
								}
							}
							foreach ($cluster_fields as $cluster_field):
						?>
								<tr class="cluster_<?php echo h($cluster_field['key']); ?>">
									<td style="width:25%;vertical-align: text-top; padding-bottom:10px;"><?php echo h(ucfirst($cluster_field['key'])); ?></td>
									<td style="width:75%; padding-bottom:10px;">
										<?php
											if (is_array($cluster_field['value'])) {
												if ($cluster_field['key'] == 'refs') {
													$value = array();
													foreach ($cluster_field['value'] as $k => $v) {
														$value[$k] = '<a href="' . h($v) . '">' . h($v) . '</a>';
													}
													echo nl2br(implode("\n", $value));
												} else if($cluster_field['key'] == 'country') {
													$value = array();
													foreach ($cluster_field['value'] as $k => $v) {
														$value[] = '<div class="famfamfam-flag-' . strtolower(h($v)) . '" ></div>&nbsp;' . h($v);
													}
													echo nl2br(implode("\n", $value));
												} else {
													echo nl2br(h(implode("\n", $cluster_field['value'])));
												}
											} else {
												 if ($cluster_field['key'] == 'source' && filter_var($cluster_field['value'], FILTER_VALIDATE_URL)) {
													 echo '<a href="' . h($cluster_field['value']) . '">' . h($cluster_field['value']) . '</a>';;
												 } else {
													echo h($cluster_field['value']);
												 }
											}
										?>
									</td>
								</tr>
						<?php
							endforeach;
						?>
					</table>
					<?php

					?>
				</div>
			</div>
<?php
		endforeach;
?>
	</div>
<?php
	endforeach;
?>
<?php
	if ($isSiteAdmin || ($mayModify && $isAclTagger)):
?>
		<span class="useCursorPointer btn btn-inverse" id="addGalaxy" data-event-id="<?php echo h($event['Event']['id']); ?>" style="margin-top:20px;padding: 1px 5px !important;font-size: 12px !important;">Add new cluster</span>
<?php
	endif;
?>

<script type="text/javascript">
$(document).ready(function () {
	$('.expandable').click(function() {
		$(this).parent().children('div').toggle();
		if ($(this).children('span').html() == '+') {
			$(this).children('span').html('-');
		} else {
			$(this).children('span').html('+');
		}
	});
	$('.delete-cluster').click(function() {
		var tagName = $(this).data('tag-name');
		removeTag($id = false, $tag_id = false, $galaxy = false);
	});
});
</script>
