<?php
	$fixed_fields = array('decription', 'source', 'authors');
	foreach ($event['Galaxy'] as $galaxy):
?>
		<div class="bold blue useCursorPointer" style="font-size:14px;">
			<span title="<?php echo isset($galaxy['description']) ? h($galaxy['description']) : h($galaxy['name']);?>" class="expandable"><?php echo h($galaxy['name']); ?></span>
	<?php
		foreach ($galaxy['GalaxyCluster'] as $cluster):
	?>
			<div style="margin-left:20px;" class="bold blue hidden useCursorPointer">
				<span class="expandable"><?php echo h($cluster['value']); ?></span>&nbsp;
				<?php
					echo $this->Form->postLink('',
						array(
							'admin' => true,
							'action' => 'delete',
							$org['Organisation']['id']
						),
						array('class' => 'icon-trash', 'title' => 'Delete'),
						__('Are you sure you want to delete %s?', $org['Organisation']['name'])
					);
				?>
				<span class="icon-trash delete-cluster" data-tag-name="<?php echo h($cluster['tag_name']);?>"></span>
				<div style="margin-left:40px;" class="hidden">
					<table style="width:100%">
						<?php
							foreach ($fixed_fields as $fixed_field):
								if (isset($cluster[$fixed_field])):
						?>
									<tr>
										<td style="width:25%;vertical-align: text-top; padding-bottom:10px;"><?php echo h(ucfirst($fixed_field)); ?></td>
										<td style="width:75%; padding-bottom:10px;">
											<?php 
												if (is_array($cluster[$fixed_field])) {	
													$cluster[$fixed_field] = implode("\n", $cluster[$fixed_field]);
													echo nl2br(h($cluster[$fixed_field]));
												} else {
													echo h($cluster[$fixed_field]);
												}
											?>
										</td>
									</tr>
						<?php
								endif;
							endforeach;
							foreach ($cluster['meta'] as $key => $value):
						?>
								<tr>
									<td style="width:25%;vertical-align: text-top; padding-bottom:10px;"><?php echo h(ucfirst($key)); ?></td>
									<td style="width:75%; padding-bottom:10px;"><?php echo nl2br(h(implode("\n", $value))); ?></td>
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
		alert(tagName);
		removeTag($id = false, $tag_id = false, $galaxy = false)
	});
});
</script>