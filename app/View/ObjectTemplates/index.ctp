<div class="objectTemplates index">
	<h2>Object Template index</h2>
	<div class="pagination">
		<ul>
			<?php
				$this->Paginator->options(array(
						'update' => '.span12',
						'evalScripts' => true,
						'before' => '$(".progress").show()',
						'complete' => '$(".progress").hide()',
				));

				echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
				echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
				echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
			?>
		</ul>
	</div>
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('name');?></th>
			<th><?php echo $this->Paginator->sort('uuid');?></th>
			<th><?php echo $this->Paginator->sort('org_id', 'Organisation');?></th>
			<th><?php echo $this->Paginator->sort('version');?></th>
			<th><?php echo $this->Paginator->sort('meta-category');?></th>
			<th><?php echo $this->Paginator->sort('description');?></th>
			<th>Requirements</th>
			<th class="actions">Actions</th>
	</tr>
	<?php
foreach ($list as $template):
	$td_attributes = 'ondblclick="document.location.href =\'/objectTemplates/view/' . h($template['ObjectTemplate']['id']) . '\'"';
	?>
	<tr>
		<td class="short" <?php echo $td_attributes; ?>><?php echo h($template['ObjectTemplate']['id']); ?></td>
		<td class="shortish" <?php echo $td_attributes; ?>>
			<?php
				if ($template['ObjectTemplate']['fixed']):
			?>
				<img src="<?php echo $baseurl;?>/img/orgs/MISP.png" width="24" height="24" style="padding-bottom:3px;" />
			<?php
				endif;
			?>
					<span class="bold"><?php echo h($template['ObjectTemplate']['name']); ?></span>
		</td>
		<td class="short" <?php echo $td_attributes; ?>><?php echo h($template['ObjectTemplate']['uuid']); ?></td>
		<td class="short" <?php echo $td_attributes; ?>><?php echo h($template['Organisation']['name']); ?></td>
		<td class="short" <?php echo $td_attributes; ?>><?php echo h($template['ObjectTemplate']['version']); ?></td>
		<td class="short" <?php echo $td_attributes; ?>><?php echo h($template['ObjectTemplate']['meta-category']); ?></td>
		<td <?php echo $td_attributes; ?>><?php echo h($template['ObjectTemplate']['description']); ?></td>
		<td <?php echo $td_attributes; ?>>
			<?php
				if (!empty($template['ObjectTemplate']['requirements'])):
					foreach ($template['ObjectTemplate']['requirements'] as $group => $requirements):
			?>
						<span class="bold"><?php echo h($group); ?></span><br />
			<?php
							foreach ($requirements as $requirement):
			?>
								<span>&nbsp;&nbsp;<?php echo h($requirement); ?></span><br />
			<?php
							endforeach;
					endforeach;
				endif;
			?>
		</td>
		<td class="short action-links">
			<a href='/objectTemplates/view/<?php echo $template['ObjectTemplate']['id']; ?>' class = "icon-list-alt" title = "View"></a>
		</td>
	</tr>
	<?php
endforeach; ?>
	</table>
	<p>
	<?php
	echo $this->Paginator->counter(array(
	'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
	));
	?>
	</p>
	<div class="pagination">
		<ul>
		<?php
			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
		?>
		</ul>
	</div>

</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'objectTemplates', 'menuItem' => 'index'));
