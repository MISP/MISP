<div class="templates view">
<?php 
	echo $this->Html->script('ajaxification');
?>
<h2><?php  echo __('Template');?></h2>
	<dl>
		<dt><?php echo __('Id'); ?></dt>
		<dd>
			<?php echo $template['Template']['id']; ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Name'); ?></dt>
		<dd>
			<?php echo h($template['Template']['name']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Description'); ?></dt>
		<dd>
			<?php echo h($template['Template']['description']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Tags'); ?></dt>
		<dd>
			<table>
				<tr id = "tags">
					<?php 
						if (!empty($template['TemplateTag'])) {
							foreach ($template['TemplateTag'] as $tag) {
								echo $this->element('ajaxTemplateTag', array('tag' => $tag));
							}
						} else echo '&nbsp';
					?>
				</tr>
			</table>
		</dd>
		<dt><?php echo __('Organisation'); ?></dt>
		<dd>
			<?php echo h($template['Template']['org']); ?>
			&nbsp;
		</dd>
		<dt><?php echo __('Shareable'); ?></dt>
		<dd>
			<?php 
				if ($template['Template']['share']) echo 'Yes';
				else echo 'No'; 
			?>
		</dd>
	</dl>
	<div id="templateElements">
	</div>
	<div id="popover_form" class="ajax_popover_form">aaa</div>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'roles'));
?>
<script type="text/javascript">
$(document).ready( function () {
	updateIndex(<?php echo $template['Template']['id']?>, 'template');
});
</script>