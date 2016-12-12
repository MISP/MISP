<?php
	$fixed_fields = array('synonyms', 'description', 'meta', 'authors', 'source');
	foreach ($event['Galaxy'] as $galaxy):
?>
		<div>
			<span title="<?php echo isset($galaxy['description']) ? h($galaxy['description']) : h($galaxy['name']);?>" class="bold blue" style="font-size:14px;">
				<?php echo h($galaxy['name']); ?>
			</span>
	<?php
		foreach ($galaxy['GalaxyCluster'] as $cluster):
	?>
			<div style="margin-left:20px;">
				<span class="bold blue expandable useCursorPointer"><?php echo h($cluster['value']); ?></span>&nbsp;
				<a href="<?php echo $baseurl; ?>/events/index/searchtag:<?php echo h($cluster['tag_id']); ?>" class="icon-th-list" title="View all events containing this cluster."></a>
				<?php
					echo $this->Form->postLink('',
						$baseurl . '/galaxy_clusters/detachFromEvent/' . $event['Event']['id'] . '/' . $cluster['tag_id'],
						array('class' => 'icon-trash', 'title' => 'Delete'),
						__('Are you sure you want to detach %s from this event?', h($cluster['value']))
					);
				?>
				<div style="margin-left:40px;" class="hidden blue">
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
							if (isset($cluster['meta'])) {
								foreach ($cluster['meta'] as $metaKey => $metaField) {
									if ($metaField != 'synonyms') {
										$cluster_fields[] = array('key' => $metaKey, 'value' => $metaField);
									}
								}
							}
							foreach ($cluster_fields as $cluster_field):
						?>
								<tr>
									<td style="width:25%;vertical-align: text-top; padding-bottom:10px;"><?php echo h(ucfirst($cluster_field['key'])); ?></td>
									<td style="width:75%; padding-bottom:10px;">
										<?php
											if (is_array($cluster_field['value'])) {
												if ($cluster_field['key'] == 'refs') {
													foreach ($cluster_field['value'] as $k => $v):
														$value[$k] = '<a href="' . h($v) . '">' . h($v) . '</a>';
													endforeach;
													echo nl2br(implode("\n", $value));
												} else {
													echo nl2br(h(implode("\n", $cluster_field['value'])));
												}
											} else {
												echo h($cluster_field['value']);
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
<script type="text/javascript">
$(document).ready(function () {
	$('.expandable').click(function() {
		$(this).parent().children('div').toggle();
	});
	$('.delete-cluster').click(function() {
		var tagName = $(this).data('tag-name');
		removeTag($id = false, $tag_id = false, $galaxy = false);
	});
});
</script>
